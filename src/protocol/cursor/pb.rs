//! Hand-written protobuf for the Cursor (`agent.v1`) wire.
//!
//! Scope: the wire primitives — varint, tag, length-delimited value, `fixed64`
//! double, `fixed32`, `bool`, embedded message — plus `google.protobuf.Value`
//! (`serde_json::Value`) encoding and decoding. Field numbers and message
//! layouts are protocol knowledge and stay with the modules that encode or
//! decode them.
//!
//! Read bounds, all fail-closed:
//!
//! * a varint longer than ten bytes, or one whose tenth byte carries more than
//!   the single remaining bit, is [`CursorError::Malformed`];
//! * a length-delimited value above [`MAX_FIELD_LEN`] is
//!   [`CursorError::TooLarge`] **before** the payload is looked at, so a
//!   declared length can never drive an allocation;
//! * a value that runs past the end of the buffer is [`CursorError::Truncated`],
//!   never a short read or a panic;
//! * wire types 3 and 4 (deprecated groups) and the two unassigned wire types
//!   are [`CursorError::Malformed`] rather than guessed at;
//! * `google.protobuf.Value` nesting above [`MAX_VALUE_DEPTH`] is
//!   [`CursorError::TooDeep`], in both directions — a deeply nested JSON tree
//!   would otherwise recurse the stack.
//!
//! Fields the caller does not recognize are simply not matched: [`Reader`]
//! yields every field, so an unknown field number (or an unexpected wire type
//! for an unknown number) is skipped by construction. For the `Value` codec that
//! means a vendor adding a field cannot break an existing stream.
//!
//! Deliberate deviations from the reference implementation (identical wire
//! bytes, stricter reads):
//!
//! * Truncation is an error; the reference's `fields()` silently drops a
//!   malformed tail (`return out`), which turns a truncated message into a
//!   short one.
//! * A non-UTF-8 string, or a `number_value` that JSON cannot represent (NaN,
//!   ±infinity), is an error. The reference decodes UTF-8 lossily (U+FFFD) and
//!   turns a non-finite double into `null` by way of `JSON.stringify`.
//! * `google.protobuf.Value` is a proto3 `oneof`, so the last arm present wins;
//!   the reference returns the first one it meets.
//! * Unknown `Value` field numbers are skipped; the reference's `pbAny`
//!   returns `null` for the first field number it does not know.

use bytes::Bytes;
use serde_json::Map;
use serde_json::Number;
use serde_json::Value;

use super::CursorError;

/// Largest accepted length-delimited payload (one field or one sub-message).
pub const MAX_FIELD_LEN: u64 = 64 << 20;

/// Largest accepted `google.protobuf.Value` nesting level. Deep enough for any
/// real tool schema or blob, far below what would risk the stack.
pub const MAX_VALUE_DEPTH: u32 = 64;

/// Wire type 0: varint (`int32/int64/uint64/bool/enum`).
const WIRE_VARINT: u8 = 0;
/// Wire type 1: eight little-endian bytes (`double`, `fixed64`).
const WIRE_FIXED64: u8 = 1;
/// Wire type 2: varint length followed by that many bytes.
const WIRE_LEN: u8 = 2;
/// Wire type 5: four little-endian bytes (`fixed32`).
const WIRE_FIXED32: u8 = 5;

/// Longest legal `u64` varint; the tenth byte holds the final bit only.
const MAX_VARINT_BYTES: u32 = 10;

// `google.protobuf.Value`'s oneof arms and the two container messages.
const VALUE_NULL: u32 = 1;
const VALUE_NUMBER: u32 = 2;
const VALUE_STRING: u32 = 3;
const VALUE_BOOL: u32 = 4;
const VALUE_STRUCT: u32 = 5;
const VALUE_LIST: u32 = 6;
/// `Struct.fields` is a `map<string, Value>`; each entry is one message here.
const STRUCT_ENTRY: u32 = 1;
/// One map entry: `1` = key, `2` = value.
const ENTRY_KEY: u32 = 1;
const ENTRY_VALUE: u32 = 2;
/// `ListValue.values`.
const LIST_ELEMENT: u32 = 1;

/// An outbound message being built.
///
/// Field numbers are protocol constants supplied by the caller; a number above
/// protobuf's 29-bit maximum is a caller bug, not something this type can
/// detect (the same is true of every hand-written encoder).
#[derive(Debug, Default)]
pub struct Writer {
    buffer: Vec<u8>,
}

impl Writer {
    pub fn new() -> Self {
        Self::default()
    }

    /// The finished message, shared rather than copied again: the caller hands
    /// it to the transport as the request body or as a frame payload.
    #[must_use]
    pub fn into_bytes(self) -> Bytes {
        Bytes::from(self.buffer)
    }

    /// A varint field (wire type 0).
    pub fn varint(&mut self, field: u32, value: u64) {
        self.head(field, WIRE_VARINT);
        put_varint(&mut self.buffer, value);
    }

    /// A `bool` field, which is a varint of 0 or 1.
    pub fn boolean(&mut self, field: u32, value: bool) {
        self.varint(field, u64::from(value));
    }

    /// A `double` field (wire type 1, little-endian).
    pub fn double(&mut self, field: u32, value: f64) {
        self.head(field, WIRE_FIXED64);
        self.buffer
            .extend_from_slice(&value.to_bits().to_le_bytes());
    }

    /// A length-delimited field: bytes, an embedded message, a `string`.
    pub fn bytes(&mut self, field: u32, value: &[u8]) {
        self.head(field, WIRE_LEN);
        put_varint(&mut self.buffer, value.len() as u64);
        self.buffer.extend_from_slice(value);
    }

    /// A `string` field: UTF-8 bytes, length-delimited.
    pub fn string(&mut self, field: u32, value: &str) {
        self.bytes(field, value.as_bytes());
    }

    /// An embedded message field. The nested message is built first and then
    /// appended once, so the payload is copied at most once per nesting level —
    /// this is request-build work, never a per-chunk path.
    pub fn message(&mut self, field: u32, nested: Writer) {
        self.bytes(field, &nested.buffer);
    }

    fn head(&mut self, field: u32, wire: u8) {
        put_varint(&mut self.buffer, (u64::from(field) << 3) | u64::from(wire));
    }
}

/// Append one varint in protobuf's little-endian base-128 form.
fn put_varint(out: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        out.push((value as u8 & 0x7F) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

/// One field of a message body.
///
/// Unknown field numbers arrive here like any other field, so a caller that
/// only matches the numbers it knows skips the rest without extra handling.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Field<'a> {
    pub number: u32,
    pub value: FieldValue<'a>,
}

/// One field's decoded value, grouped by wire type.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum FieldValue<'a> {
    /// Wire type 0. `bool` and enums are varints too; the caller interprets it.
    Varint(u64),
    /// Wire type 1: eight little-endian bytes, kept as the raw bits so a
    /// `double` is `f64::from_bits(..)` at the read site only.
    Fixed64(u64),
    /// Wire type 2: a borrowed slice of the message body — never a copy.
    Bytes(&'a [u8]),
    /// Wire type 5: four little-endian bytes.
    Fixed32(u32),
}

/// Field cursor over one message body.
///
/// `Item` is a [`Result`] so a malformed body ends the iteration instead of
/// panicking; the reader drains itself on the first error, which keeps a `for`
/// loop from spinning on the same failure.
#[derive(Clone, Debug)]
pub struct Reader<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    pub fn new(input: &'a [u8]) -> Self {
        Self { input, offset: 0 }
    }

    fn read_field(&mut self) -> Result<Field<'a>, CursorError> {
        let tag = read_varint(self.input, &mut self.offset)?;
        let number = tag >> 3;
        // Field number 0 is invalid; the 29-bit maximum keeps the cast lossless.
        if number == 0 || number > u64::from(u32::MAX) {
            return Err(CursorError::Malformed);
        }
        let number = number as u32;
        let wire = (tag & 0x07) as u8;
        let value = match wire {
            WIRE_VARINT => FieldValue::Varint(read_varint(self.input, &mut self.offset)?),
            WIRE_FIXED64 => FieldValue::Fixed64(u64::from_le_bytes(read_array::<8>(
                self.input,
                &mut self.offset,
            )?)),
            WIRE_FIXED32 => FieldValue::Fixed32(u32::from_le_bytes(read_array::<4>(
                self.input,
                &mut self.offset,
            )?)),
            WIRE_LEN => {
                let length = read_varint(self.input, &mut self.offset)?;
                if length > MAX_FIELD_LEN {
                    return Err(CursorError::TooLarge);
                }
                let length = length as usize;
                let end = self
                    .offset
                    .checked_add(length)
                    .filter(|end| *end <= self.input.len())
                    .ok_or(CursorError::Truncated)?;
                let payload = self
                    .input
                    .get(self.offset..end)
                    .ok_or(CursorError::Truncated)?;
                self.offset = end;
                FieldValue::Bytes(payload)
            }
            // Deprecated groups and the two unassigned wire types: refused,
            // because guessing at their length would desynchronize the cursor.
            _ => return Err(CursorError::Malformed),
        };
        Ok(Field { number, value })
    }
}

impl<'a> Iterator for Reader<'a> {
    type Item = Result<Field<'a>, CursorError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset >= self.input.len() {
            return None;
        }
        match self.read_field() {
            Ok(field) => Some(Ok(field)),
            Err(error) => {
                self.offset = self.input.len();
                Some(Err(error))
            }
        }
    }
}

/// Read one varint, advancing `offset`. Ten bytes is the widest legal encoding.
fn read_varint(input: &[u8], offset: &mut usize) -> Result<u64, CursorError> {
    let mut value = 0u64;
    for index in 0..MAX_VARINT_BYTES {
        let byte = *input.get(*offset).ok_or(CursorError::Truncated)?;
        *offset += 1;
        // The tenth byte can only contribute bit 63: anything wider is a
        // corrupt or hostile encoding, not a large number.
        if index == MAX_VARINT_BYTES - 1 && byte > 1 {
            return Err(CursorError::Malformed);
        }
        value |= u64::from(byte & 0x7F) << (index * 7);
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    Err(CursorError::Malformed)
}

/// Read a fixed-size little-endian array, advancing `offset`.
fn read_array<const N: usize>(input: &[u8], offset: &mut usize) -> Result<[u8; N], CursorError> {
    let end = offset
        .checked_add(N)
        .filter(|end| *end <= input.len())
        .ok_or(CursorError::Truncated)?;
    let slice = input.get(*offset..end).ok_or(CursorError::Truncated)?;
    let array = <[u8; N]>::try_from(slice).map_err(|_| CursorError::Truncated)?;
    *offset = end;
    Ok(array)
}

/// Decode one `google.protobuf.Value` message body.
///
/// An empty message is the oneof's default arm, `null_value`, which is
/// [`Value::Null`].
pub fn decode_value(input: &[u8]) -> Result<Value, CursorError> {
    value_body(input, 1)
}

/// Encode one JSON value as the `google.protobuf.Value` embedded in `field`.
pub fn write_value(out: &mut Writer, field: u32, value: &Value) -> Result<(), CursorError> {
    let mut body = Writer::new();
    write_value_body(&mut body, value, 1)?;
    out.message(field, body);
    Ok(())
}

/// `depth` is this value's own nesting level; its members are one deeper.
fn value_body(input: &[u8], depth: u32) -> Result<Value, CursorError> {
    if depth > MAX_VALUE_DEPTH {
        return Err(CursorError::TooDeep);
    }
    let mut decoded = Value::Null;
    for field in Reader::new(input) {
        let field = field?;
        match (field.number, field.value) {
            (VALUE_NULL, FieldValue::Varint(_)) => decoded = Value::Null,
            (VALUE_NUMBER, FieldValue::Fixed64(bits)) => {
                let double = f64::from_bits(bits);
                decoded = number_value(double)?;
            }
            (VALUE_STRING, FieldValue::Bytes(payload)) => {
                decoded = Value::String(text(payload)?.to_owned());
            }
            (VALUE_BOOL, FieldValue::Varint(flag)) => decoded = Value::Bool(flag != 0),
            (VALUE_STRUCT, FieldValue::Bytes(payload)) => {
                decoded = Value::Object(object_body(payload, depth + 1)?);
            }
            (VALUE_LIST, FieldValue::Bytes(payload)) => {
                decoded = Value::Array(list_body(payload, depth + 1)?);
            }
            // A known number with the wrong wire type is a corrupt message, not
            // a field to skip.
            (
                VALUE_NULL | VALUE_NUMBER | VALUE_STRING | VALUE_BOOL | VALUE_STRUCT | VALUE_LIST,
                _,
            ) => {
                return Err(CursorError::Malformed);
            }
            // Unknown field number: skipped (see the module docs).
            _ => {}
        }
    }
    Ok(decoded)
}

/// `Struct{ fields: map<string, Value> }`; `member_depth` is the depth of the
/// member values, whose entries are therefore at that level.
fn object_body(input: &[u8], member_depth: u32) -> Result<Map<String, Value>, CursorError> {
    let mut entries = Map::new();
    for field in Reader::new(input) {
        let field = field?;
        if field.number != STRUCT_ENTRY {
            continue;
        }
        let FieldValue::Bytes(entry) = field.value else {
            return Err(CursorError::Malformed);
        };
        let mut key: Option<&str> = None;
        let mut item = Value::Null;
        for entry_field in Reader::new(entry) {
            let entry_field = entry_field?;
            match (entry_field.number, entry_field.value) {
                (ENTRY_KEY, FieldValue::Bytes(payload)) => key = Some(text(payload)?),
                (ENTRY_VALUE, FieldValue::Bytes(payload)) => {
                    item = value_body(payload, member_depth)?;
                }
                (ENTRY_KEY | ENTRY_VALUE, _) => return Err(CursorError::Malformed),
                _ => {}
            }
        }
        // A map entry without a key has no JSON representation; a missing value
        // is protobuf's default, `null_value`.
        let key = key.ok_or(CursorError::Malformed)?;
        // Duplicate keys are protobuf map semantics: the last entry wins.
        entries.insert(key.to_owned(), item);
    }
    Ok(entries)
}

/// `ListValue{ values: repeated Value }`.
fn list_body(input: &[u8], element_depth: u32) -> Result<Vec<Value>, CursorError> {
    let mut elements = Vec::new();
    for field in Reader::new(input) {
        let field = field?;
        if field.number != LIST_ELEMENT {
            continue;
        }
        let FieldValue::Bytes(payload) = field.value else {
            return Err(CursorError::Malformed);
        };
        elements.push(value_body(payload, element_depth)?);
    }
    Ok(elements)
}

/// `number_value` is a double; JSON has no NaN or infinity, so one that cannot
/// be represented is a decode failure instead of a silent `null`. An integral
/// double inside the exactly-representable range comes back as a JSON
/// integer: tool arguments like `{"count": 3}` must reach the caller as `3`,
/// not `3.0`.
fn number_value(double: f64) -> Result<Value, CursorError> {
    if !double.is_finite() {
        return Err(CursorError::Malformed);
    }
    const EXACT: f64 = 9_007_199_254_740_992.0; // 2^53
    if double.fract() == 0.0 && double.abs() < EXACT {
        return Ok(if double >= 0.0 {
            Value::from(double as u64)
        } else {
            Value::from(double as i64)
        });
    }
    Number::from_f64(double)
        .map(Value::Number)
        .ok_or(CursorError::Malformed)
}

/// A `string` field's text. Invalid UTF-8 is an error, never a lossy decode.
/// A length-delimited field read as a protobuf `string` (UTF-8 required).
pub fn text(payload: &[u8]) -> Result<&str, CursorError> {
    std::str::from_utf8(payload).map_err(|_| CursorError::Malformed)
}

/// `depth` is this value's own nesting level; its members are one deeper.
fn write_value_body(out: &mut Writer, value: &Value, depth: u32) -> Result<(), CursorError> {
    if depth > MAX_VALUE_DEPTH {
        return Err(CursorError::TooDeep);
    }
    match value {
        Value::Null => out.varint(VALUE_NULL, 0),
        Value::Bool(flag) => out.boolean(VALUE_BOOL, *flag),
        Value::Number(number) => {
            // A `serde_json` number always narrows to a double unless the
            // arbitrary-precision feature is on; refuse rather than emit 0.
            let double = number.as_f64().ok_or(CursorError::Malformed)?;
            out.double(VALUE_NUMBER, double);
        }
        Value::String(string) => out.string(VALUE_STRING, string),
        Value::Array(elements) => {
            let mut list = Writer::new();
            for element in elements {
                let mut encoded = Writer::new();
                write_value_body(&mut encoded, element, depth + 1)?;
                list.message(LIST_ELEMENT, encoded);
            }
            out.message(VALUE_LIST, list);
        }
        Value::Object(entries) => {
            let mut object = Writer::new();
            // `serde_json`'s default map is ordered by key, so the encoding is
            // deterministic (the reference sorts too).
            for (key, item) in entries {
                let mut entry = Writer::new();
                entry.string(ENTRY_KEY, key);
                let mut encoded = Writer::new();
                write_value_body(&mut encoded, item, depth + 1)?;
                entry.message(ENTRY_VALUE, encoded);
                object.message(STRUCT_ENTRY, entry);
            }
            out.message(VALUE_STRUCT, object);
        }
    }
    Ok(())
}
