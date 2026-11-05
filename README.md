# Cardinal

A headless LLM gateway that routes requests across multiple AI providers with failover, quota awareness, and usage metering.

## Features

- **Multi-provider routing** — Route requests to multiple providers (Kimi, DeepSeek, GLM, OpenAI-compatible, Anthropic, etc.) with ordered or quota-aware (smart) strategies
- **Protocol translation** — Accept OpenAI Chat Completions, OpenAI Responses, Anthropic Messages, and Gemini API requests; translate between protocols automatically
- **Embeddings passthrough** — Serve OpenAI-style `POST /v1/embeddings` (OpenAI, SiliconFlow, Jina, Voyage, Ollama, …) across the same routes, failover and metering as chat; retrieval calls are forwarded verbatim with only the model id rewritten
- **Failover & cooldown** — Automatic failover to the next candidate on errors, with per-key cooldown tracking; a Kiro account can opt out of the 429 cooldown (account card menu → 429 不冷却), retrying in place and then failing over without resting
- **Quota monitoring** — Periodic probing of provider quota/balance endpoints; quota-aware routing decisions
- **Usage metering** — Per-request token counting and cost calculation (USD) with provider/model price tables
- **Concurrency control** — Per-key concurrency limits with semaphore-based queuing
- **Availability rules** — Per-route time-window and weekday rules (allow/deny) for route-entry availability
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

## Deployment

On SIGTERM or Ctrl-C the gateway stops accepting new connections, waits up to
120s for in-flight requests (including long SSE streams) to finish, waits up to
20s more for finished streams to record their usage and charges, flushes and
settles the buffered ledger rows, then exits. Streams still open after 120s are
cut.

systemd's default stop timeout (90s) is shorter than that, so the unit must
raise it, or systemd will SIGKILL the process before the final ledger flush and
unsettled charges are lost:

```ini
[Service]
ExecStart=/opt/cardinal/cardinal-gateway
KillSignal=SIGTERM
TimeoutStopSec=150
Restart=always
```

A single instance still has a gap of a few seconds during a restart when new
connections are refused. Zero-downtime restarts would need several instances
with socket handoff, which is not implemented.

## API Overview

| Endpoint | Description |
|----------|-------------|
| `POST /v1/chat/completions` | OpenAI Chat Completions |
| `POST /v1/responses` | OpenAI Responses API |
| `POST /v1/messages` | Anthropic Messages |
| `POST /v1/embeddings` | OpenAI Embeddings (retrieval, passthrough) |
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
| `GET/POST /api/users`, `GET/PATCH /api/users/{id}` | Billing users |
| `POST /api/users/{id}/topup`, `POST /api/users/{id}/adjust` | Balance changes (USD) |
| `GET /api/users/{id}/entries`, `GET /api/users/{id}/reconcile` | Billing ledger and balance check (also each key's spend against its charges) |
| `GET/POST /api/user-groups`, `PATCH /api/user-groups/{id}` | User groups (rate multiplier, route whitelist) |
| `GET/POST /api/gateway-keys`, `PATCH /api/gateway-keys/{id}` | Gateway keys: label (unique per user), owner, expiry, cumulative USD quota, enabled |
| `GET /user/me`, `GET /user/me/entries` | Self-service balance, keys and ledger (gateway key auth) |
| `GET/POST /user/keys`, `PATCH /user/keys/{id}` | Self-service keys: list (full key), create `{label, expires_at?, quota_usd?}`, edit `{label?, enabled?, expires_at?, quota_usd?}` (null clears expiry/quota); at most 20 keys per user, disabled included (409); another user's key is 404; no delete |
| `GET /user/usage/window`, `GET /user/usage/trend` | Self-service usage; trend `split` = `route` (default), `model` or `client` (`provider`/`user` → 400) |

Admin endpoints under `/api` require `Authorization: Bearer <admin key>`;
`/v1` and `/user` endpoints require a gateway key.

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
