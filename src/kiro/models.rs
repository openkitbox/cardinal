//! Kiro's model catalogue knowledge that is independent of the wire
//! translation: how a configured GPT alias names a canonical vendor model.

/// The GPT-5.6 discriminating tokens (reference `mapModel`): `sol`, `terra`,
/// `luna`, and the `codex` alias for the flagship. A bare `gpt-5.6` names no
/// variant and is refused. `lower` must already be trimmed and lowercased.
///
/// The canonical id is also the id the vendor's model catalogue
/// (`ListAvailableModels`) lists, so the relay's metadata lookup resolves a
/// configured alias to the same snapshot entry through this one mapping.
pub fn gpt_model(lower: &str) -> Option<&'static str> {
    if lower.contains("sol") {
        return Some("gpt-5.6-sol");
    }
    if lower.contains("terra") {
        return Some("gpt-5.6-terra");
    }
    if lower.contains("luna") {
        return Some("gpt-5.6-luna");
    }
    if lower.contains("codex") {
        return Some("gpt-5.6-sol");
    }
    None
}
