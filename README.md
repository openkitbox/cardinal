# Cardinal

A headless LLM gateway that routes requests across multiple AI providers with failover, quota awareness, and usage metering.

The companion native macOS management dashboard is available in the [Cardinal GUI](https://github.com/openkitbox/cardinal-gui) repository. It connects to a running Cardinal gateway over the HTTP API and SSE activity stream.

## Features

- **Multi-provider routing** — Route requests to multiple providers (Kimi, DeepSeek, GLM, OpenAI-compatible, Anthropic, etc.) with ordered or quota-aware (smart) strategies
- **Protocol translation** — Accept OpenAI Chat Completions, OpenAI Responses, Anthropic Messages, and Gemini API requests; translate between protocols automatically
- **Embeddings passthrough** — Serve OpenAI-style `POST /v1/embeddings` (OpenAI, SiliconFlow, Jina, Voyage, Ollama, …) across the same routes, failover and metering as chat; retrieval calls are forwarded verbatim with only the model id rewritten
- **Failover & cooldown** — Automatic failover to the next candidate on errors, with per-key cooldown tracking; a Kiro account can opt out of the 429 cooldown (account card menu → 429 不冷却), retrying in place and then failing over without resting
- **Quota monitoring** — Periodic probing of provider quota/balance endpoints; quota-aware routing decisions
- **Usage metering** — Per-request token counting and cost calculation (USD) with provider/model price tables; Kiro reports no cache split, so the gateway simulates prompt-cache reads (a prefix resent by the same caller to the same account and model within 5 minutes bills at the cache-read price)
- **Concurrency control** — Per-key concurrency limits with semaphore-based queuing
- **Availability rules** — Per-route time-window and weekday rules (allow/deny) for route-entry availability
- **Admin API** — Full HTTP management API (providers, keys, routes, pricing, quotas, activity)
- **SSE activity stream** — Real-time event feed of all gateway activity
- **TLS** — Optional TLS via rustls (configured in config file)
- **Vendor dialects** — Automatic handling of provider-specific quirks (GLM thinking mode, DeepSeek tool-call pairing, image stripping)

## Quick Start

### Prerequisites

- Rust stable toolchain
- PostgreSQL 18+
- TimescaleDB 2.31.0+ installed and enabled in the database (the migration intentionally does not create the extension)

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

### Customer portal local integration

The customer portal is deliberately opt-in: registration is enabled only with
an explicit non-internal customer group. Only deployment policy stays in TOML:

```toml
[gateway.portal]
default_customer_group = "customer"   # must not be `owner` or `internal`
bff_secret = "local-bff-secret"       # shared with the Cloudflare Web BFF
```

`bff_secret` must match the Web BFF's `GATEWAY_BFF_SECRET`; no configured secret
means `POST /auth/oauth/exchange` rejects every request. The Web side also needs
`CARDINAL_URL` (Gateway base URL) and `OAUTH_STATE_SECRET` (signs the one-time
OAuth state cookie). Provider client secrets stay in Gateway — never in Web
environment variables or frontend code.

Mail transport (HTTP or SMTP) and Google/GitHub OAuth providers live in
PostgreSQL, are managed through the Gateway admin API or the GUI settings page,
and take effect immediately. There is no `[gateway.portal.mail]` TOML section;
configure mail after Gateway health with `PUT /api/portal/settings`:

```bash
curl -H "Authorization: Bearer your-admin-key" \
  -H 'Content-Type: application/json' \
  -X PUT http://127.0.0.1:8787/api/portal/settings \
  -d '{"mail_transport":"http",
       "mail_url":"http://127.0.0.1:18080/send",
       "mail_token":"local-mail-secret",
       "mail_from":"Cardinal <auth@example.test>",
       "mail_origin":"http://127.0.0.1:5173",
       "smtp_host":"","smtp_port":25,"smtp_username":"",
       "smtp_password":"","smtp_tls":"starttls","smtp_from":""}'
```

Login providers use `GET /api/portal/providers` and
`PUT/DELETE /api/portal/providers/{provider}` (`google` or `github`). The public
`GET /auth/oauth/providers` lists only enabled providers and never exposes
secrets. `client_id`, `client_secret`, `redirect_uri` and `enabled` are stored in
the DB; dev-only loopback endpoint overrides under `extra.endpoints` in the
provider record require `[gateway] allow_insecure_upstream = true`. Never enable
that flag in production.

An account created only through OAuth has a random, unusable password hash; if
its owner explicitly completes the email forgot/reset-password flow, it becomes
a dual-mode account that can log in both with email+password and through the
linked OAuth provider (unverified emails are never auto-linked).

The reproducible Web integration command is run from the companion Web checkout:

```bash
export CARDINAL_TEST_DATABASE_URL='postgres://cardinal:password@127.0.0.1:5432/cardinal_test'
cd ../cardinal-web
bun run test:e2e
```

`bun run test:e2e` creates an isolated PostgreSQL 18/TimescaleDB Docker container
when `CARDINAL_TEST_DATABASE_URL` is not set, starts mock mail and OAuth provider
HTTP endpoints, configures the Gateway with a temporary customer group, a BFF
secret, mail settings via `PUT /api/portal/settings` after `/health` is ready,
and a GitHub login provider, then starts the real Gateway and Web servers with
the environment variables above. It also uses a local OpenAI-compatible upstream
fixture. It polls readiness and mail/usage conditions with bounded timeouts; it
does not read a home-directory config, production DSN, or live credentials. Set
`CARDINAL_GATEWAY_ROOT` when the Gateway worktree is not at the default adjacent
path.

Use PostgreSQL 18 with TimescaleDB >= 2.31 for integration tests. The local
fixture image `timescale/timescaledb:latest-pg18` currently provides a compatible
TimescaleDB version and initializes the extension in `template1`; a fresh test
database should execute `CREATE EXTENSION IF NOT EXISTS timescaledb` before
migrations when the fixture owns database creation.

The portal E2E covers open registration and fragment mail verification, account
and Key login, OAuth login through loopback-provider mocks, two customer keys, a
real mocked upstream request, aggregate vs single-Key usage, billing,
unavailable top-up, forgot/reset, logout, and second-user isolation. Payment
providers, orders, webhooks, real mail reachability, real Google/GitHub
endpoints, production routing, and production admin-surface isolation are not
covered by the local test.

Check the gateway is up with:

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

## Docker（新环境一键体验）

For a quick trial in a new environment, a single public image is all you need —
PostgreSQL 18 + TimescaleDB and the Cardinal binary are all inside this one
image:

```bash
docker run -d --name cardinal \
  -p 8787:8787 \
  -v cardinal-data:/data \
  -e GATEWAY_KEY=<your-admin-key> \
  ghcr.io/openkitbox/cardinal:latest
```

`GATEWAY_KEY` is required and the value you enter must match `[A-Za-z0-9_-]+`.

Only data lives in the `cardinal-data` volume; no Compose file and no external
database are needed. View logs with `docker logs cardinal`. Stop with
`docker stop -t 150 cardinal` — Cardinal drains in-flight work and settles the
ledger for up to ~140s, so the 10s default stop timeout would cut it off. If an
admin GUI outside the container must reach `/api/*`, also pass
`-e ADMIN_REMOTE=true`.

This is for new-environment one-click trials only and does not replace the
systemd deployment above. cloudflared is not included in the image.

The image is built only when a `v*` tag is pushed (for example
`git tag v1.0.0 && git push origin v1.0.0`) or the Docker workflow is triggered
manually; ordinary pushes to `main` do not start a CI build. A tag build also
updates the `latest` tag.

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
`/v1` endpoints require a gateway key; `/user/*` accepts account portal
sessions, key portal sessions, and raw gateway keys. Existing billing users are
not automatically provisioned account credentials, and registration does not
backfill credentials onto them.

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
