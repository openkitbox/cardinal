//! Simulated prompt-cache reads for Kiro.
//!
//! KAS reports no cached-token split: its usage is a context percentage and a
//! credit count (see [`crate::protocol::kiro`]). Every Kiro prompt would
//! therefore bill as uncached input even when the client resends the same
//! conversation prefix turn after turn. This module simulates the vendor-side
//! prompt cache the way the reference `kiro.rs` does
//! (`src/anthropic/cache_metering.rs`, OpenAI auto-caching): the end of every
//! completed prompt is remembered for a sliding [`TTL`], and a later prompt
//! whose prefix ends at a remembered boundary reads that prefix as cached.
//! "Completed" means the attempt reached its terminal: a parsed JSON body, or
//! a stream that delivered its finish event. An attempt that fails after the
//! 2xx headers (abort, read error, broken stream) neither reads nor writes.
//!
//! Only `cached_input_tokens` is produced. A first-seen prefix bills as plain
//! input, never as a cache write (decided 2026-11-05; Chat usage has no write
//! field either).
//!
//! Deliberate deviations from `kiro.rs`, each toward fewer discounts:
//!
//! * **A block is one message**, plus one head block for the system prompt and
//!   tool declarations, so the 20-block lookback counts messages. The
//!   reference counts content blocks with tool runs folded.
//! * **A prefix shorter than [`MIN_CACHEABLE_TOKENS`] is never cached**,
//!   matching Anthropic's real floor; the reference's OpenAI path has none.
//! * **No persistence and no shared backend.** A restart or a second replica
//!   starts cold, which can only withhold a discount, never invent one.
//! * **Scope**: the upstream account, the gateway key that called and the
//!   upstream model all seed the digest, so one caller never reads another's
//!   prefix. In-process calls with no gateway key are not cached at all.
//! * **Fail closed on price**: a model with no cache-read price (stored as 0,
//!   or no price at all) is not cached, so a simulated hit never bills free.
//!
//! Thinking parts take no part: the Kiro emitter drops them from history
//! (`translation::kiro`), so they never reach the vendor.
//!
//! Shape: [`Prefix::of`] is pure (digest + estimate of the prompt), [`Hit`] is
//! the pure split applied to the observed usage, [`PromptCache`] is a plain
//! expiry map with no policy of its own, and [`PendingRead`] carries an
//! accepted prompt to the point its attempt completes.

use std::collections::HashMap;
use std::io;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use sha2::{Digest as _, Sha256};

use crate::protocol::usage::UsageCounts;
use crate::store::ModelPrice;
use crate::translation::ir::{FileSource, ImageSource, IrMessage, IrPart, IrRequest, IrRole};

/// Sliding lifetime of a remembered prefix (Anthropic's ephemeral default).
const TTL: Duration = Duration::from_secs(5 * 60);
/// How many block boundaries, counted back from the end of the prompt, a
/// lookup probes for a remembered prefix (Anthropic's 20-block lookback).
const LOOKBACK_BLOCKS: usize = 20;
/// The shortest prefix (estimated tokens) that is ever cached; Anthropic's
/// floor for its larger models.
const MIN_CACHEABLE_TOKENS: u64 = 1_024;
/// Entry ceiling (~4 MB). A full map first drops expired entries (at most once
/// per [`SWEEP_INTERVAL`]); if it is still full the new boundary is not
/// remembered, which only withholds a later discount.
const CAPACITY: usize = 65_536;
/// The least time between two expiry sweeps of a full map, so a map full of
/// live entries does not rescan itself on every request.
const SWEEP_INTERVAL: Duration = Duration::from_secs(30);
/// Images and files count as a fixed estimate: their base64 length says
/// nothing about their token cost (Anthropic bills ~1600 for a 1.15 MP image).
const ATTACHMENT_TOKENS: u64 = 1_600;

type BoundaryHash = [u8; 16];

/// Who may read a prefix: the upstream account, the calling gateway key and
/// the upstream model.
#[derive(Clone, Copy, Debug)]
pub struct Scope<'a> {
    pub account_key_id: i64,
    pub caller_key_id: i64,
    pub model: &'a str,
}

/// One prompt's block boundaries: the digest of everything up to the end of
/// each block, with the estimated tokens up to there.
#[derive(Debug)]
pub struct Prefix {
    boundaries: Vec<Boundary>,
}

#[derive(Clone, Copy, Debug)]
struct Boundary {
    hash: BoundaryHash,
    tokens: u64,
}

impl Prefix {
    /// Digest the IR prompt the Kiro emitter is built from, block by block.
    /// Every attachment counts [`ATTACHMENT_TOKENS`], including one the
    /// emitter cannot forward; the estimate only sets the cached share.
    #[must_use]
    pub fn of(scope: Scope<'_>, request: &IrRequest) -> Self {
        let mut hasher = Sha256::new();
        feed_str(&mut hasher, "cardinal-kiro-prompt-cache-v1");
        hasher.update(scope.account_key_id.to_le_bytes());
        hasher.update(scope.caller_key_id.to_le_bytes());
        feed_str(&mut hasher, scope.model);

        let mut boundaries = Vec::with_capacity(request.messages.len() + 1);
        let mut tokens = feed_head(&mut hasher, request);
        if tokens > 0 {
            boundaries.push(boundary(&hasher, tokens));
        }
        for message in &request.messages {
            tokens = tokens.saturating_add(feed_message(&mut hasher, message));
            boundaries.push(boundary(&hasher, tokens));
        }
        Self { boundaries }
    }

    fn total_tokens(&self) -> u64 {
        self.boundaries.last().map_or(0, |last| last.tokens)
    }
}

/// A remembered prefix this prompt starts with: `cached` of the prompt's
/// `total` estimated tokens.
#[derive(Clone, Copy, Debug)]
pub struct Hit {
    cached: u64,
    total: u64,
}

impl Hit {
    /// Write the cached share of the observed prompt into `usage`.
    ///
    /// The estimate and the observed `input_tokens` use different scales, so
    /// the hit is carried over as a ratio (the reference's
    /// `split_against_total`). `input_tokens` stays the whole prompt: Chat's
    /// `cached_tokens` is a subset of `prompt_tokens`. A vendor-reported split
    /// is never overwritten.
    pub fn apply(self, usage: &mut UsageCounts) {
        if usage.cached_input_tokens.is_some() || self.total == 0 {
            return;
        }
        let share =
            u128::from(usage.input_tokens) * u128::from(self.cached) / u128::from(self.total);
        let cached = u64::try_from(share)
            .unwrap_or(u64::MAX)
            .min(usage.input_tokens);
        usage.cached_input_tokens = Some(cached);
    }
}

/// Apply an optional hit to optional usage: no hit or no usage leaves it as is.
#[must_use]
pub fn with_hit(usage: Option<UsageCounts>, hit: Option<Hit>) -> Option<UsageCounts> {
    let mut usage = usage?;
    if let Some(hit) = hit {
        hit.apply(&mut usage);
    }
    Some(usage)
}

/// Whether a simulated hit may bill at this price: every unit (base and each
/// tier) must carry a real cache-read price. An unset one is stored as 0 and
/// would bill the cached share as free; no price at all bills nothing to split.
#[must_use]
pub fn prices_cache_reads(price: Option<&ModelPrice>) -> bool {
    price.is_some_and(|price| {
        price.cache_read_usd > 0.0 && price.tiers.iter().all(|tier| tier.cache_read_usd > 0.0)
    })
}

/// The remembered prompt ends: boundary digest → expiry.
#[derive(Clone, Default)]
pub struct PromptCache {
    entries: Arc<Mutex<Entries>>,
}

#[derive(Default)]
struct Entries {
    expiries: HashMap<BoundaryHash, Instant>,
    /// When a full map was last swept; `None` = never.
    swept_at: Option<Instant>,
}

impl PromptCache {
    pub fn new() -> Self {
        Self::default()
    }

    fn read_and_remember_at(&self, prefix: &Prefix, now: Instant) -> Option<Hit> {
        let last = *prefix.boundaries.last()?;
        let Ok(mut entries) = self.entries.lock() else {
            tracing::warn!("prompt cache lock poisoned; no simulated cache read");
            return None;
        };
        let Entries { expiries, swept_at } = &mut *entries;
        let expires = now + TTL;
        let mut cached = None;
        for boundary in prefix.boundaries.iter().rev().take(LOOKBACK_BLOCKS) {
            if let Some(expiry) = expiries.get_mut(&boundary.hash)
                && *expiry > now
            {
                *expiry = expires;
                cached = Some(boundary.tokens);
                break;
            }
        }
        if last.tokens >= MIN_CACHEABLE_TOKENS {
            let known = expiries.contains_key(&last.hash);
            let sweep_due = swept_at.is_none_or(|at| now >= at + SWEEP_INTERVAL);
            if expiries.len() >= CAPACITY && !known && sweep_due {
                expiries.retain(|_, expiry| *expiry > now);
                *swept_at = Some(now);
            }
            if expiries.len() < CAPACITY || known {
                expiries.insert(last.hash, expires);
            } else {
                tracing::debug!("prompt cache full; prompt end not remembered");
            }
        }
        cached.map(|cached| Hit {
            cached,
            total: prefix.total_tokens(),
        })
    }
}

/// A prompt the vendor accepted (2xx), waiting for its attempt to complete.
/// Dropping it unsettled (the attempt failed) leaves the cache untouched.
pub struct PendingRead {
    cache: PromptCache,
    prefix: Prefix,
}

impl PendingRead {
    pub fn new(cache: &PromptCache, prefix: Prefix) -> Self {
        Self {
            cache: cache.clone(),
            prefix,
        }
    }

    /// The attempt completed: find the deepest remembered boundary within the
    /// lookback (renewing it), then remember this prompt's own end.
    #[must_use]
    pub fn settle(self) -> Option<Hit> {
        self.cache
            .read_and_remember_at(&self.prefix, Instant::now())
    }
}

fn boundary(hasher: &Sha256, tokens: u64) -> Boundary {
    let digest = hasher.clone().finalize();
    let mut hash = [0u8; 16];
    hash.copy_from_slice(&digest[..16]);
    Boundary { hash, tokens }
}

/// The head block: system prompt and tool declarations.
fn feed_head(hasher: &mut Sha256, request: &IrRequest) -> u64 {
    hasher.update([0x10]);
    let mut tokens = 0u64;
    if let Some(system) = request.system.as_deref() {
        feed_str(hasher, system);
        tokens = tokens.saturating_add(text_tokens(system));
    }
    for tool in &request.tools {
        hasher.update([0x11]);
        feed_str(hasher, &tool.name);
        feed_str(hasher, &tool.description);
        let schema_len = feed_json(hasher, &tool.schema);
        tokens = tokens
            .saturating_add(text_tokens(&tool.name))
            .saturating_add(text_tokens(&tool.description))
            .saturating_add(schema_len / 4);
    }
    tokens
}

fn feed_message(hasher: &mut Sha256, message: &IrMessage) -> u64 {
    hasher.update([match message.role {
        IrRole::User => 0x20,
        IrRole::Assistant => 0x21,
    }]);
    message.parts.iter().fold(0u64, |tokens, part| {
        tokens.saturating_add(feed_part(hasher, part))
    })
}

fn feed_part(hasher: &mut Sha256, part: &IrPart) -> u64 {
    match part {
        IrPart::Text(text) => {
            hasher.update([0x30]);
            feed_str(hasher, text);
            text_tokens(text)
        }
        IrPart::Image { media, source } => {
            hasher.update([0x31]);
            feed_str(hasher, media);
            feed_str(
                hasher,
                match source {
                    ImageSource::Base64(data) | ImageSource::Url(data) => data,
                },
            );
            ATTACHMENT_TOKENS
        }
        IrPart::File { media, source } => {
            hasher.update([0x32]);
            feed_str(hasher, media);
            feed_str(
                hasher,
                match source {
                    FileSource::Base64(data) | FileSource::Url(data) => data,
                },
            );
            ATTACHMENT_TOKENS
        }
        IrPart::ToolCall { id, name, args } => {
            hasher.update([0x33]);
            feed_str(hasher, id.as_deref().unwrap_or(""));
            feed_str(hasher, name);
            let args_len = feed_json(hasher, args);
            text_tokens(name).saturating_add(args_len / 4)
        }
        IrPart::ToolResult {
            call_id,
            text,
            images,
            is_error,
        } => {
            hasher.update([0x34, u8::from(*is_error)]);
            feed_str(hasher, call_id);
            feed_str(hasher, text);
            // Counted, so a result's own images never hash like a result
            // followed by separate image parts.
            hasher.update((images.len() as u64).to_le_bytes());
            images.iter().fold(text_tokens(text), |tokens, image| {
                tokens.saturating_add(feed_part(hasher, image))
            })
        }
        // Dropped by the Kiro emitter: never on the wire, never cached.
        IrPart::Thinking { .. } => 0,
    }
}

/// Length-framed so adjacent fields can never run together.
fn feed_str(hasher: &mut Sha256, text: &str) {
    hasher.update((text.len() as u64).to_le_bytes());
    hasher.update(text.as_bytes());
}

/// Serialize straight into the digest (JSON is self-delimiting) and return the
/// serialized length for the token estimate. No intermediate `String`.
fn feed_json(hasher: &mut Sha256, value: &serde_json::Value) -> u64 {
    let mut writer = DigestWriter { hasher, written: 0 };
    // The writer is infallible and a `Value` always serializes, so the
    // discarded error can never be produced.
    let _ = serde_json::to_writer(&mut writer, value);
    writer.written
}

/// The output-token estimate the Kiro kernel uses too: chars / 4.
fn text_tokens(text: &str) -> u64 {
    (text.chars().count() / 4) as u64
}

struct DigestWriter<'a> {
    hasher: &'a mut Sha256,
    written: u64,
}

impl io::Write for DigestWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.hasher.update(bytes);
        self.written = self.written.saturating_add(bytes.len() as u64);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
