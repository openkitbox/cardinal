//! Connect protocol (version 1) framing for Cursor's streamed agent calls.
//!
//! One frame is `[flags: u8][len: u32 big-endian][payload: len bytes]`. Flag
//! bit 0 marks a gzip-compressed payload; bit 1 marks the stream's end frame,
//! whose payload is JSON (`{}` or `{"error": {…}}`) rather than a protobuf
//! message. Remaining bits are reserved and passed through untouched.
//!
//! [`Framer`] is the downlink reader. Its input is a socket byte stream, so a
//! chunk boundary can fall anywhere: inside the header, inside a payload, or
//! after several whole frames. A frame is only yielded once every one of its
//! bytes has arrived, its payload being a [`Bytes::slice`] of the receive
//! buffer rather than a copy. End-of-input is decided by the caller: [`Framer::finish`]
//! refuses a leftover partial frame instead of dropping it, so a truncated
//! stream can never look like a clean end.
//!
//! [`encode_frame`] is the uplink writer used for `BidiAppend` requests.
//!
//! Deliberate deviations from the reference implementation (identical bytes on
//! the wire, stricter reads):
//!
//! * Compression is refused ([`CursorError::Compressed`]) rather than
//!   gunzipped: this client never negotiates Connect compression, so a gzip
//!   frame means the peer ignored the negotiation, and inflating untrusted
//!   input is a decompression-bomb surface nobody here needs. The refusal
//!   happens as soon as the header is read, before the payload is buffered.
//! * A declared length above [`MAX_INBOUND_PAYLOAD`] is
//!   [`CursorError::TooLarge`] before any buffering; the reference compares
//!   against the same bound but only after concatenating its accumulation
//!   buffer chunks.
//! * A malformed frame is terminal: the framer is dropped instead of
//!   resynchronized, because the length field is the only thing that could
//!   place the next frame and it just proved untrustworthy.
//!
//! **Compression note for the uplink:** [`encode_frame`] always writes
//! `flags = 0`, so the frame body is the protobuf message exactly. Cursor's
//! downlink frames are read uncompressed for the reason above.

use bytes::Bytes;
use bytes::BytesMut;

use super::CursorError;

/// The fixed frame header: one flags byte and a big-endian payload length.
const HEADER: usize = 5;

/// Flag bit 0: the payload is gzip-compressed.
const FLAG_COMPRESSED: u8 = 0x01;

/// Flag bit 1: this frame ends the stream and its payload is JSON.
const FLAG_END_OF_STREAM: u8 = 0x02;

/// Largest frame payload accepted from the upstream (plan §2.3).
///
/// A hostile or confused peer must not be able to make the gateway buffer
/// unbounded data: the bound is applied to the declared length, before a single
/// payload byte is awaited.
pub const MAX_INBOUND_PAYLOAD: usize = 64 << 20;

/// One Connect stream frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    /// The raw flags byte (see the module docs).
    pub flags: u8,
    /// The frame body: a protobuf message, or JSON when [`Frame::is_end`].
    /// A slice of the receive buffer, so it shares that allocation.
    pub payload: Bytes,
}

impl Frame {
    /// Whether this is the stream's end frame. Its payload is JSON — `{}` for a
    /// clean end, `{"error": {…}}` for a failure — and it is the only frame
    /// that carries no protobuf message.
    #[must_use]
    pub fn is_end(&self) -> bool {
        self.flags & FLAG_END_OF_STREAM != 0
    }

    /// An end frame carrying `json` — what the Run driver synthesizes when it
    /// must end the stream itself (an uplink failure, a silence verdict, a
    /// step whose tool count never came), in the same shape the peer uses so
    /// every reader sees one wire.
    #[must_use]
    pub fn end(json: impl Into<Bytes>) -> Self {
        Self {
            flags: FLAG_END_OF_STREAM,
            payload: json.into(),
        }
    }

    /// Re-encode this frame as it was on the wire (header and payload), for a
    /// reader that wants the whole body back as bytes.
    pub fn encode(&self) -> Result<Bytes, CursorError> {
        let length = u32::try_from(self.payload.len()).map_err(|_| CursorError::TooLarge)?;
        let mut frame = Vec::with_capacity(HEADER + self.payload.len());
        frame.push(self.flags);
        frame.extend_from_slice(&length.to_be_bytes());
        frame.extend_from_slice(&self.payload);
        Ok(Bytes::from(frame))
    }
}

/// Incremental Connect frame splitter.
///
/// An error is terminal: the caller drops the framer rather than trying to
/// resynchronize a stream whose only framing information is untrustworthy.
#[derive(Debug, Default)]
pub struct Framer {
    buffer: BytesMut,
}

impl Framer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Append one chunk and return the frames it completed — none, one, or
    /// several, in wire order.
    pub fn push(&mut self, chunk: &[u8]) -> Result<Vec<Frame>, CursorError> {
        self.buffer.extend_from_slice(chunk);
        let mut frames = Vec::new();
        while let Some(frame) = self.next_frame()? {
            frames.push(frame);
        }
        Ok(frames)
    }

    /// The stream ended here: clean only when no partial frame is buffered.
    pub fn finish(&self) -> Result<(), CursorError> {
        if self.buffer.is_empty() {
            Ok(())
        } else {
            Err(CursorError::Truncated)
        }
    }

    fn next_frame(&mut self) -> Result<Option<Frame>, CursorError> {
        if self.buffer.len() < HEADER {
            return Ok(None);
        }
        let header = self.buffer.get(..HEADER).ok_or(CursorError::Truncated)?;
        let flags = header[0];
        let length = u32::from_be_bytes([header[1], header[2], header[3], header[4]]) as usize;
        if length > MAX_INBOUND_PAYLOAD {
            return Err(CursorError::TooLarge);
        }
        // Refuse before buffering a payload that could not be read anyway.
        if flags & FLAG_COMPRESSED != 0 {
            return Err(CursorError::Compressed);
        }
        // `length` is already bounded by `MAX_INBOUND_PAYLOAD`, so this total
        // cannot overflow.
        let total = HEADER + length;
        if self.buffer.len() < total {
            return Ok(None);
        }
        let frame = self.buffer.split_to(total).freeze();
        Ok(Some(Frame {
            flags,
            payload: frame.slice(HEADER..),
        }))
    }
}

/// Wrap one protobuf message as a client frame (`flags = 0`) for the uplink
/// `BidiAppend` request stream.
///
/// The header length is a `u32`, so a payload that cannot be expressed is
/// [`CursorError::TooLarge`] instead of a silently wrapped length.
/// [`MAX_INBOUND_PAYLOAD`] is deliberately not applied: that bound exists to
/// keep untrusted input from dictating our memory use, while an outbound frame
/// is our own message and KV blobs can legitimately be large.
pub fn encode_frame(payload: &[u8]) -> Result<Bytes, CursorError> {
    let length = u32::try_from(payload.len()).map_err(|_| CursorError::TooLarge)?;
    let mut frame = Vec::with_capacity(HEADER + payload.len());
    frame.push(0);
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(payload);
    Ok(Bytes::from(frame))
}
