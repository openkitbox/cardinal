//! Three-state JSON fields for partial updates: absent = untouched, `null`
//! = clear, value = set. Shared by the admin and self-service request bodies.

use serde::Deserialize;

/// Presence-capturing deserializer for a tri-state field: serde only calls
/// this when the field is present, so wrapping in Some marks "explicitly
/// supplied" (null → Some(None)); absence falls back to the field default.
/// Use as `#[serde(default, deserialize_with = "crate::tri_state::deserialize")]`.
pub fn deserialize<'de, D, T>(deserializer: D) -> Result<Option<Option<T>>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Ok(Some(Option::<T>::deserialize(deserializer)?))
}
