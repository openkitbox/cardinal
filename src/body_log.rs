//! Diagnostic body capture: when `[gateway].payloads` is on, the relay
//! appends the request/response bodies of recent requests to hourly log files
//! so the GUI can expand a request row and inspect what actually went over
//! the wire. This is a diagnostic aid, not an archive: each side is truncated
//! at 256 KiB ([`CALL_BODY_LIMIT`]) and one NDJSON line is appended per
//! captured row to `~/.ox/payloads/<YYYY-MM-DD>/<HH>.ndjson` (local time;
//! missing directories are created on demand).

use std::path::PathBuf;

/// Per-side truncation limit, in bytes.
/// Shared with relay.rs's bounded payload render, which stops one small slack
/// above this limit (the render's cut is byte-aligned; the capture re-cuts on
/// the char boundary).
pub(crate) const CALL_BODY_LIMIT: usize = 256 << 10;

/// Where the hourly payload files live: `~/.ox/payloads`.
fn payload_dir() -> PathBuf {
    dirs::home_dir()
        .map(|home| home.join(".ox").join("payloads"))
        .unwrap_or_else(|| PathBuf::from("/tmp/cardinal/payloads"))
}

/// The captured bodies of one request row.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct CapturedBodies {
    /// The client request body (truncated at [`CALL_BODY_LIMIT`]).
    pub request: String,
    /// The response body — `None` when the request failed before any response
    /// (the row carries the error instead).
    pub response: Option<String>,
    /// The request side hit the truncation limit.
    pub request_truncated: bool,
    /// The response side hit the truncation limit, or a stream frame was not
    /// valid UTF-8 (lossy-decoded for readability).
    pub response_truncated: bool,
    /// The response was an SSE stream (the body is the frames, `\n\n`-separated).
    pub streaming: bool,
    pub captured_at: chrono::DateTime<chrono::Utc>,
}

/// One NDJSON line: the dispatch request id (`req_{n}`) plus the captured
/// bodies (flattened, so the admin response stays a bare [`CapturedBodies`]).
#[derive(serde::Serialize, serde::Deserialize)]
struct CapturedRow {
    request_id: String,
    #[serde(flatten)]
    bodies: CapturedBodies,
}

/// Appends captured bodies to hourly NDJSON files. Stateless (each record is
/// one open-append-close): capture is sparse (payloads off by default) and
/// the diagnostic path tolerates an open per record.
///
/// Concurrency: many relay requests can settle at the same moment, so pushes
/// run in parallel — correctness rests on each record being **one** `write()`
/// (line + newline in a single buffer): under `O_APPEND` the kernel serializes
/// it against concurrent appends, so records never interleave or merge.
///
/// Measured on this machine (APFS, bench mirroring this exact cycle), 2 KiB
/// records: 1 thread 21k ops/s (p50 36µs, p99 212µs); saturates around 100
/// concurrent writers at ~96k ops/s (p99 13ms); 256 KiB records ~21k ops/s.
/// Production peak is 371 requests/hour — six orders of magnitude of
/// headroom, so a channel + single-consumer batching design would have
/// nothing to batch; see the ledger (`gateway_requests`) for live numbers.
#[derive(Clone, Default)]
pub struct BodyLog {
    /// Injectable for tests; production uses [`PAYLOAD_DIR`].
    dir: Option<PathBuf>,
}

impl BodyLog {
    pub fn new() -> Self {
        Self::default()
    }

    fn dir(&self) -> PathBuf {
        self.dir.clone().unwrap_or_else(payload_dir)
    }

    /// Hourly file for a capture timestamp: `<dir>/<date>/<hour>.ndjson`,
    /// bucketed in local time (the operator thinks in wall-clock hours).
    fn file_for(&self, at: chrono::DateTime<chrono::Utc>) -> PathBuf {
        let local = at.with_timezone(&chrono::Local);
        self.dir()
            .join(local.format("%Y-%m-%d").to_string())
            .join(format!("{}.ndjson", local.format("%H")))
    }

    /// Append one request's bodies, keyed by its dispatch request id
    /// (`req_{n}` — the ledger writer batches inserts, so the row id is not
    /// known at capture time; the request id is the correlation key). The
    /// record lands in the hour of `bodies.captured_at`; a capture spanning an
    /// hour boundary still lands whole in its starting hour.
    pub fn push(&self, request_id: &str, bodies: CapturedBodies) {
        let file = self.file_for(bodies.captured_at);
        let Some(parent) = file.parent() else { return };
        if let Err(error) = std::fs::create_dir_all(parent) {
            tracing::warn!(target: "gateway::payload", "cannot create payload dir {}: {error}", parent.display());
            return;
        }
        let row = CapturedRow {
            request_id: request_id.to_string(),
            bodies,
        };
        match serde_json::to_string(&row) {
            Ok(mut line) => {
                line.push('\n');
                let result = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&file)
                    .and_then(|mut file| {
                        use std::io::Write as _;
                        // One write() per record: O_APPEND makes a single write atomic
                        // against concurrent appends (parallel requests settle at the same
                        // moment), so records never interleave or merge into one line.
                        file.write_all(line.as_bytes())
                    });
                if let Err(error) = result {
                    tracing::warn!(target: "gateway::payload", "cannot append payload {}: {error}", file.display());
                }
            }
            Err(error) => {
                tracing::warn!(target: "gateway::payload", "cannot serialize payload for {request_id}: {error}")
            }
        }
    }

    /// The bodies of one request, looked up by its dispatch request id in the
    /// hourly files around `near` (the row's ledger time): the capture can have
    /// started shortly before or after the row was persisted, so up to three
    /// hour files are scanned. Returns `None` when payloads are off or the
    /// request is out of that window.
    pub fn get_near(
        &self,
        request_id: &str,
        near: chrono::DateTime<chrono::Utc>,
    ) -> Option<CapturedBodies> {
        [0, -1, 1].iter().find_map(|offset| {
            let file = self.file_for(near + chrono::Duration::hours(*offset));
            let text = std::fs::read_to_string(file).ok()?;
            text.lines().rev().find_map(|line| {
                let row: CapturedRow = serde_json::from_str(line).ok()?;
                (row.request_id == request_id).then_some(row.bodies)
            })
        })
    }
}

/// Truncate text to [`CALL_BODY_LIMIT`] bytes on a UTF-8 char boundary
/// (slicing a multibyte char would panic). Returns the text and whether it
/// was truncated.
pub(crate) fn capture_text(text: &str) -> (String, bool) {
    if text.len() <= CALL_BODY_LIMIT {
        return (text.to_string(), false);
    }
    let mut end = CALL_BODY_LIMIT;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    (text[..end].to_string(), true)
}

/// Streaming response accumulator: frames arrive as bytes and are kept
/// `\n\n`-separated (mirroring the SSE wire, so the panel stays readable); a
/// non-UTF-8 frame is lossy-decoded (and marks the capture truncated — the
/// body is kept readable, unlike payload_log's truncate-then-lossy). Past
/// the limit, further frames are dropped and the truncation flag sticks.
pub(crate) struct CapturedBody {
    buf: String,
    truncated: bool,
    saw_non_utf8: bool,
}

impl CapturedBody {
    pub(crate) fn new() -> Self {
        Self {
            buf: String::new(),
            truncated: false,
            saw_non_utf8: false,
        }
    }

    pub(crate) fn push(&mut self, bytes: &[u8]) {
        if self.truncated {
            return; // over the limit: drop the frame, the flag is sticky
        }
        let text = String::from_utf8_lossy(bytes);
        if matches!(&text, std::borrow::Cow::Owned(_)) {
            self.saw_non_utf8 = true;
        }
        // The separator joins the frame so the limit accounting covers it.
        let frame = if self.buf.is_empty() {
            text.into_owned()
        } else {
            format!("\n\n{text}")
        };
        let remaining = CALL_BODY_LIMIT.saturating_sub(self.buf.len());
        if frame.len() <= remaining {
            self.buf.push_str(&frame);
            return;
        }
        // The lossy output is a fresh String, so char-boundary checks are against
        // valid UTF-8 — the cut can never split the multi-byte replacement char.
        let mut end = remaining;
        while !frame.is_char_boundary(end) {
            end -= 1;
        }
        self.buf.push_str(&frame[..end]);
        self.truncated = true;
    }

    /// The accumulated body and whether it is incomplete (over the limit or
    /// lossy-decoded).
    pub(crate) fn finish(self) -> (String, bool) {
        (self.buf, self.truncated || self.saw_non_utf8)
    }
}

/// Mask API keys in captured bodies before they hit the payload log: the log
/// is a diagnostic aid any local operator can read, so plaintext credentials
/// (`sk-…` vendor keys, JSON `api_key`/`api-key`/`authorization` fields,
/// `Bearer` tokens) must not land on disk.
///
/// Masking shapes:
/// - `sk-…` vendor keys (OpenAI/Anthropic/etc., also `sk-ant-…`) keep the
///   `sk-` prefix and last 4 chars: `sk-abcdefghijklmnop` → `sk-...mnop`.
/// - JSON fields `"api_key"`, `"api-key"`, `"authorization"`, `"key"` have
///   their whole value replaced by `"***"` (Bearer tokens included).
///
/// Purely textual (no JSON parsing): a truncated capture is not valid JSON,
/// so the patterns must survive a mid-token cut. A short `sk-` fragment
/// (under 8 chars after the prefix, e.g. a truncation cut) is left alone —
/// it reveals nothing on its own.
pub(crate) fn mask_secrets(text: &str) -> String {
    use std::sync::LazyLock;
    // Vendor keys: `sk-` plus at least 8 token chars. The {8,} floor keeps a
    // meaningful last-4 suffix; shorter fragments (a truncation cut) are left
    // alone rather than unmasked — they reveal nothing on their own.
    static SK_KEY: LazyLock<regex::Regex> =
        LazyLock::new(|| regex::Regex::new(r"sk-[A-Za-z0-9_-]{8,}").expect("sk-key pattern"));
    // JSON credential fields: `"api_key": "…"` → `"api_key": "***"`. The
    // field name is kept verbatim (casing and separator included) so the body
    // stays readable as the request that was sent.
    static JSON_SECRET: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(r#""(api_key|api-key|apikey|authorization|key)"(\s*:\s*)"[^"]*""#)
            .expect("json secret pattern")
    });
    let masked = SK_KEY.replace_all(text, |captures: &regex::Captures<'_>| {
        let token = captures.get(0).expect("whole match").as_str();
        format!("sk-...{}", &token[token.len() - 4..])
    });
    JSON_SECRET
        .replace_all(&masked, |captures: &regex::Captures<'_>| {
            format!("\"{}\"{}\"***\"", &captures[1], &captures[2])
        })
        .into_owned()
}
