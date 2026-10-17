# Cardinal

A headless LLM gateway that routes requests across multiple AI providers with failover, quota awareness, and usage metering.

## Features

- **Multi-provider routing** — Route requests to multiple providers (Kimi, DeepSeek, GLM, OpenAI-compatible, Anthropic, etc.) with ordered or quota-aware (smart) strategies
- **Protocol translation** — Accept OpenAI Chat Completions, OpenAI Responses, Anthropic Messages, and Gemini API requests; translate between protocols automatically
- **Failover & cooldown** — Automatic failover to the next candidate on errors, with per-key cooldown tracking
- **Quota monitoring** — Periodic probing of provider quota/balance endpoints; quota-aware routing decisions
- **Usage metering** — Per-request token counting and cost calculation (USD) with provider/model price tables
- **Concurrency control** — Per-key concurrency limits with semaphore-based queuing
- **Availability rules** — Per-route time-window and weekday rules (allow/deny) for provider availability
- **Admin API** — Full HTTP management API (providers, keys, routes, pricing, quotas, activity)
- **SSE activity stream** — Real-time event feed of all gateway activity
- **TLS** — Optional TLS via rustls (configured in config file)
- **Vendor dialects** — Automatic handling of provider-specific quirks (GLM thinking mode, DeepSeek tool-call pairing, image stripping)

## Quick Start

### Prerequisites

- Rust stable toolchain
- PostgreSQL

### Configuration

Create `~/.ox/config.toml`:

```toml
[gateway]
listen = "127.0.0.1:8787"
sql_dsn = "postgres://user:pass@127.0.0.1:5432/cardinal"
key = "your-admin-key"

# Optional TLS
# [gateway.ssl]
# cert_path = "/path/to/cert.pem"
# key_path = "/path/to/key.pem"
```

### Run

```bash
cargo build --release
./target/release/cardinal
```

### Verify

```bash
curl -H "Authorization: Bearer your-admin-key" http://127.0.0.1:8787/api/info
```

## API Overview

| Endpoint | Description |
|----------|-------------|
| `POST /v1/chat/completions` | OpenAI Chat Completions |
| `POST /v1/responses` | OpenAI Responses API |
| `POST /v1/messages` | Anthropic Messages |
| `POST /v1beta/models/{model}:generateContent` | Gemini |
| `GET /v1/models` | List available models |
| `GET /api/info` | Gateway status |
| `GET /api/providers` | List providers |
| `POST /api/keys` | Create API key |
| `GET /api/routes` | List routes |
| `PUT /api/routes/{alias}` | Create/update route |
| `GET /api/requests` | Query request ledger |
| `GET /api/quotas` | Provider quota snapshots |
| `GET /api/activity` | SSE activity stream |

All admin endpoints require `Authorization: Bearer <key>`.

## Architecture

```
Client → Cardinal (protocol translation) → Upstream Provider
                │
                ├─ relay/          — dispatch loop, failover, streaming
                ├─ relay/dialects  — vendor-specific fixups
                ├─ protocol/       — request/response format parsers
                ├─ translation/    — cross-protocol translation
                ├─ store/          — PostgreSQL persistence
                ├─ metering        — usage counting & pricing
                └─ quota           — provider quota probing
```

## License

GPL-3.0-only
