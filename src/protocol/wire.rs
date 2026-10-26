//! Response-wire framing selection for the relay pump.
//!
//! The gateway consumes two upstream response wires:
//!
//! * SSE ([`sse::Framer`]) — every client-facing protocol;
//! * AWS Event Stream ([`awseventstream::Framer`]) — Kiro's KAS upstream only.
//!
//! [`WireFramer`] chooses the framer from the protocol, so the transport reads
//! one closed [`WireFrame`] union instead of branching on protocol per chunk.
//! The choice is explicit: Kiro is the only protocol whose response is not
//! SSE, and a future non-SSE protocol must extend [`WireFramer::for_protocol`]
//! rather than inherit SSE by accident.
//!
//! These framers only ever read the upstream wire. Client-bound frames —
//! including the terminal frames the client-protocol decoder synthesizes for a
//! truncated stream — are always rendered as SSE, so an AWS message can never
//! reach a client.

use super::ProtocolId;
use super::{awseventstream, sse};

/// One complete upstream frame, in whichever wire its protocol uses.
///
/// Deliberately not `Clone`: the pump passes each frame through once, and a
/// clone would invite a per-frame payload copy on the hot path.
#[derive(Debug, PartialEq, Eq)]
pub enum WireFrame {
    Sse(sse::RawFrame),
    Aws(awseventstream::Message),
}

impl WireFrame {
    /// The SSE frame, when this wire is SSE. The passthrough pump forwards SSE
    /// frames verbatim; the AWS wire is only ever a translation source, so it
    /// has no passthrough representation.
    pub fn as_sse(&self) -> Option<&sse::RawFrame> {
        match self {
            Self::Sse(frame) => Some(frame),
            Self::Aws(_) => None,
        }
    }
}

/// Framing failure on either wire. Terminal: the caller drops the framer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WireError {
    Sse(sse::SseError),
    Aws(awseventstream::AwsError),
}

/// The incremental framer for one response wire.
pub enum WireFramer {
    Sse(sse::Framer),
    Aws(awseventstream::Framer),
}

impl WireFramer {
    /// The framer for `protocol`'s response wire. KAS answers in AWS Event
    /// Stream framing; every client-facing protocol answers in SSE.
    pub fn for_protocol(protocol: ProtocolId) -> Self {
        // Exhaustive on purpose: a new protocol must state its wire here
        // instead of inheriting SSE by omission.
        match protocol {
            ProtocolId::Kiro => Self::Aws(awseventstream::Framer::new()),
            ProtocolId::OpenAiChat
            | ProtocolId::OpenAiResponses
            | ProtocolId::AnthropicMessages
            | ProtocolId::Gemini
            | ProtocolId::OpenAiEmbeddings => Self::Sse(sse::Framer::new()),
        }
    }

    /// Append one socket chunk; return every frame it completed.
    pub fn push(&mut self, chunk: &[u8]) -> Result<Vec<WireFrame>, WireError> {
        match self {
            Self::Sse(framer) => framer
                .push_raw(chunk)
                .map(|frames| frames.into_iter().map(WireFrame::Sse).collect())
                .map_err(WireError::Sse),
            Self::Aws(framer) => framer
                .push(chunk)
                .map(|messages| messages.into_iter().map(WireFrame::Aws).collect())
                .map_err(WireError::Aws),
        }
    }

    /// The stream ended. SSE flushes a trailing partial event exactly as the
    /// pre-abstraction reader did; an AWS frame cut short by EOF is
    /// [`awseventstream::AwsError::Truncated`] — never a silent clean end.
    pub fn finish(&mut self) -> Result<Vec<WireFrame>, WireError> {
        match self {
            Self::Sse(framer) => framer
                .finish_raw()
                .map(|frames| frames.into_iter().map(WireFrame::Sse).collect())
                .map_err(WireError::Sse),
            Self::Aws(framer) => {
                framer.finish().map_err(WireError::Aws)?;
                Ok(Vec::new())
            }
        }
    }
}
