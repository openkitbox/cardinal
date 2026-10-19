//! Stable placeholders, the placeholder key, and the durable re-mask index.
//!
//! A placeholder is `{{KIND_<suffix>}}` where the suffix is derived from
//! `HMAC-SHA256(key, KIND "\0" value)` and truncated to 8 base32 chars. Deriving
//! it from the value makes it **stable**: the same value is the same placeholder
//! in every request, which keeps upstream prompt caches and vendor-signed
//! reasoning valid across turns (magpie `internal/redact`).
//!
//! Two lifetimes, deliberately separated:
//!
//! - **One request**: `placeholder -> value`, so the response can be restored.
//!   It lives in the request's [`MaskCtx`](super::MaskCtx) and dies with it.
//! - **Beyond one request**: a value the client replays **as prose** in a later
//!   turn is invisible to any stateless rule, and re-masking it is the only
//!   thing that stops a restored secret from leaking back upstream. That memory
//!   cannot be per process — a restart would drop it and the very next turn
//!   would leak (observed). It is a durable, append-only index written one
//!   encrypted record per value, so a restart keeps protecting every value
//!   already seen.
//!
//! The index holds the values themselves (encrypted at rest with a key derived
//! from the placeholder key) because re-finding a value later is a substring
//! search; the placeholder is stored beside it so a replayed placeholder still
//! resolves. A value that a rule would find again is *not* indexed — the index
//! only holds what would otherwise be invisible.

use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use sha2::{Digest, Sha256};

use super::{Repl, Span};

/// Shortest value remembered for re-masking (shorter ones turn up in ordinary text).
/// Shortest operator term worth remembering (a word; shorter would over-mask).
const MIN_TERM: usize = 8;
/// Shortest rule-derived secret worth remembering: a rule already judged it a
/// secret, so a short one (`abc123`) is still a real secret replayed bare.
const MIN_SECRET: usize = 4;
/// Shortest string the re-mask scan looks at (below the shortest secret).
const MIN_KNOWN: usize = MIN_SECRET;
/// Most values the index holds. Beyond it a new value is simply not remembered
/// (the values already there keep working) rather than evicting one that would
/// then leak on its next replay.
const MAX_ENTRIES: usize = 100_000;

static KEY: OnceLock<[u8; 32]> = OnceLock::new();
static INDEX: OnceLock<Mutex<Index>> = OnceLock::new();

/// The values seen so far that no rule would catch again, and their placeholders.
#[derive(Default)]
pub(crate) struct Index {
    path: Option<PathBuf>,
    entries: Vec<Entry>,
    /// First byte of the value -> entry indices, so a string is only searched
    /// for the values that could possibly appear in it.
    by_first: HashMap<u8, Vec<usize>>,
    by_ph: HashMap<String, String>,
}

struct Entry {
    value: String,
    ph: String,
}

/// Load the placeholder key from `path` (created 0600 if absent); without a
/// usable path a per-process random key is used, so placeholders stay stable
/// within a run but not across restarts. Call once at startup, before
/// [`init_index`].
pub(crate) fn init_key(path: Option<&Path>) {
    let _ = KEY.set(read_or_make(path));
}

/// Load the durable re-mask index from `path`. Call once at startup, after
/// [`init_key`] (the index is encrypted with a key derived from the placeholder
/// key).
pub(crate) fn init_index(path: Option<&Path>) {
    let mut index = Index::default();
    if let Some(path) = path {
        index.path = Some(path.to_path_buf());
        index.load();
    }
    let _ = INDEX.set(Mutex::new(index));
}

fn index() -> &'static Mutex<Index> {
    INDEX.get_or_init(|| Mutex::new(Index::default()))
}

/// The lock is poisoned only by a panic while it was held (nothing here
/// panics), and the data is still consistent — recover rather than take the
/// gateway down.
fn locked<T>(lock: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    lock.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// The placeholder for `value` of `kind` — a pure derivation, no state.
pub(crate) fn placeholder_for(kind: &str, value: &str) -> String {
    let mut msg = Vec::with_capacity(kind.len() + 1 + value.len());
    msg.extend_from_slice(kind.as_bytes());
    msg.push(0);
    msg.extend_from_slice(value.as_bytes());
    let digest = hmac_sha256(key(), &msg);
    let mut ph = String::with_capacity(kind.len() + 13);
    ph.push_str("{{");
    ph.push_str(kind);
    ph.push('_');
    ph.push_str(&base32_suffix(&digest));
    ph.push_str("}}");
    ph
}

/// Remember `value` for re-masking (durable), unless a rule would find it again.
/// A value a rule derived from its *context* (`password=…`) is exactly the case
/// this exists for: replayed bare it matches nothing, so it must be indexed.
/// The floor is lower for a rule-derived secret than for an operator term, which
/// is only a word and would over-mask ordinary text at that length.
pub(crate) fn remember(kind: &str, value: &str, ph: &str) {
    let floor = if kind == "TERM" { MIN_TERM } else { MIN_SECRET };
    if value.len() < floor || super::rules::matches_any(value) {
        return;
    }
    let mut index = locked(index());
    if index.by_ph.contains_key(ph) {
        return;
    }
    if index.entries.len() >= MAX_ENTRIES {
        tracing::warn!(
            entries = index.entries.len(),
            "privacy index is full; new values are no longer remembered for re-masking"
        );
        return;
    }
    index.insert(value, ph);
}

/// The value a placeholder stands for, if the durable index knows it.
pub(crate) fn resolve(ph: &str) -> Option<String> {
    let index = locked(index());
    index.by_ph.get(ph).cloned()
}

/// Spans in `s` that are a remembered value (replaced by its placeholder).
pub(crate) fn known_spans(s: &str) -> Vec<Span> {
    if s.len() < MIN_KNOWN {
        return Vec::new();
    }
    locked(index()).scan(s, false)
}

/// Spans in `s` that are a remembered value, for storage: the same values, but
/// replaced by `[REDACTED:KIND]`. A remembered value is by definition one no rule
/// finds again, so the scrub must consult the index too or the log keeps it.
pub(crate) fn redacted_spans(s: &str) -> Vec<Span> {
    if s.len() < MIN_KNOWN {
        return Vec::new();
    }
    locked(index()).scan(s, true)
}

/// The KIND of a `{{KIND_suffix}}` placeholder (`suffix` may contain `_`).
fn kind_of(ph: &str) -> &str {
    let body = ph.trim_start_matches("{{").trim_end_matches("}}");
    match body.rsplit_once('_') {
        Some((kind, _)) => kind,
        None => "SECRET",
    }
}

impl Index {
    fn load(&mut self) {
        let Some(path) = self.path.clone() else {
            return;
        };
        let Ok(text) = std::fs::read_to_string(&path) else {
            return;
        };
        for line in text.lines() {
            let Some((nonce, body)) = line.split_once(':') else {
                continue;
            };
            let (Ok(nonce), Ok(body)) = (hex::decode(nonce), hex::decode(body)) else {
                continue;
            };
            if nonce.len() != 12 {
                continue;
            }
            let Some(plain) = decrypt(&nonce, &body) else {
                tracing::warn!(path = %path.display(), "privacy index record dropped (undecryptable)");
                continue;
            };
            let Ok((value, ph)) = serde_json::from_slice::<(String, String)>(&plain) else {
                continue;
            };
            self.add(value, ph);
        }
    }

    fn insert(&mut self, value: &str, ph: &str) {
        self.add(value.to_string(), ph.to_string());
        self.persist(value, ph);
    }

    fn add(&mut self, value: String, ph: String) {
        self.by_first
            .entry(value.as_bytes()[0])
            .or_default()
            .push(self.entries.len());
        self.by_ph.insert(ph.clone(), value.clone());
        self.entries.push(Entry { value, ph });
    }

    /// Append one encrypted record. Append-only, so adding a value costs one
    /// line regardless of how many are already indexed.
    fn persist(&self, value: &str, ph: &str) {
        let Some(path) = self.path.as_ref() else {
            return;
        };
        let Ok(plain) = serde_json::to_vec(&(value, ph)) else {
            return;
        };
        let Some(record) = encrypt(&plain) else {
            tracing::warn!("privacy index record not encrypted; value not persisted");
            return;
        };
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let mut line = record.into_bytes();
        line.push(b'\n');
        let opened = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path);
        match opened {
            Ok(mut file) => {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = file.set_permissions(std::fs::Permissions::from_mode(0o600));
                }
                if let Err(e) = file.write_all(&line) {
                    tracing::warn!(error = %e, "privacy index not persisted");
                }
            }
            Err(e) => tracing::warn!(error = %e, "privacy index not persisted"),
        }
    }

    fn scan(&self, s: &str, redact: bool) -> Vec<Span> {
        if self.entries.is_empty() {
            return Vec::new();
        }
        let mut present = [false; 256];
        for &b in s.as_bytes() {
            present[b as usize] = true;
        }
        let mut out = Vec::new();
        for (first, list) in &self.by_first {
            if !present[*first as usize] {
                continue;
            }
            for &at in list {
                let entry = &self.entries[at];
                let mut from = 0;
                while let Some(found) = s[from..].find(entry.value.as_str()) {
                    let start = from + found;
                    let repl = if redact {
                        Repl::Fixed(format!("[REDACTED:{}]", kind_of(&entry.ph)))
                    } else {
                        Repl::Fixed(entry.ph.clone())
                    };
                    out.push(Span {
                        start,
                        end: start + entry.value.len(),
                        repl,
                    });
                    from = start + entry.value.len();
                }
            }
        }
        out
    }
}

fn key() -> &'static [u8; 32] {
    KEY.get_or_init(|| read_or_make(None))
}

/// The AEAD key for the index file: a subkey of the placeholder key, so both
/// live and die with the same secret.
fn index_key() -> [u8; 32] {
    hmac_sha256(key(), b"privacy-index-aead")
}

fn encrypt(plain: &[u8]) -> Option<String> {
    let cipher = ChaCha20Poly1305::new_from_slice(&index_key()).ok()?;
    let nonce = *uuid::Uuid::new_v4().as_bytes();
    let nonce = &nonce[..12];
    let body = cipher.encrypt(&aead_nonce(nonce)?, plain).ok()?;
    Some(format!("{}:{}", hex::encode(nonce), hex::encode(body)))
}

fn decrypt(nonce: &[u8], body: &[u8]) -> Option<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new_from_slice(&index_key()).ok()?;
    cipher.decrypt(&aead_nonce(nonce)?, body).ok()
}

fn aead_nonce(bytes: &[u8]) -> Option<Nonce> {
    Nonce::try_from(bytes).ok()
}

fn read_or_make(path: Option<&Path>) -> [u8; 32] {
    if let Some(path) = path {
        if let Ok(bytes) = std::fs::read(path)
            && bytes.len() >= 32
        {
            let mut k = [0u8; 32];
            k.copy_from_slice(&bytes[..32]);
            return k;
        }
        let k = random_key();
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        if let Err(e) = write_private(path, &k) {
            tracing::warn!(path = %path.display(), error = %e, "privacy key not persisted; placeholders will not survive a restart");
        }
        return k;
    }
    random_key()
}

fn write_private(path: &Path, k: &[u8; 32]) -> std::io::Result<()> {
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = f.set_permissions(std::fs::Permissions::from_mode(0o600));
    }
    f.write_all(k)
}

fn random_key() -> [u8; 32] {
    // Not a cryptographic RNG; enough to keep placeholders unguessable to an
    // observer who does not hold the key file.
    let mut k = [0u8; 32];
    let seed = format!(
        "{}{}{:?}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
        std::thread::current().id()
    );
    let mut h = Sha256::new();
    h.update(seed.as_bytes());
    h.update(uuid::Uuid::new_v4().as_bytes());
    k.copy_from_slice(&h.finalize());
    k
}

const B32: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

/// The first 8 base32 chars (40 bits) of the digest.
fn base32_suffix(digest: &[u8; 32]) -> String {
    let mut out = String::with_capacity(8);
    let mut buf = 0u64;
    let mut bits = 0u32;
    for &b in digest.iter().take(5) {
        buf = (buf << 8) | b as u64;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(B32[((buf >> bits) & 31) as usize] as char);
        }
    }
    out
}

fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    const B: usize = 64;
    let mut k = [0u8; B];
    if key.len() > B {
        let d = Sha256::digest(key);
        k[..32].copy_from_slice(&d);
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; B];
    let mut opad = [0x5cu8; B];
    for i in 0..B {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(msg);
    let inner = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner);
    outer.finalize().into()
}
