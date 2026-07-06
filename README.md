# Edge Gateway

Privacy-preserving fraud signal gateway for financial institutions. Sits inside a bank's infrastructure, strips PII from transactions, and forwards anonymized fraud signals to the IntelFraud Hub for cross-institutional pattern detection.

## Architecture

```
Bank Core System ──POST /process──> Edge Gateway ──anonymize──> Hub API
                                         │
                                    PII stays here
                                    (never leaves bank)
```

**No raw PII leaves the bank.** The gateway replaces personally identifiable information with keyed HMAC-SHA256 pseudonyms (identity mosaics), privacy-preserving tiers, and geohash zones before forwarding to the Hub. Note this is *pseudonymization*, not full anonymization: parties holding the HMAC keys (salt/pepper) could dictionary-attack low-entropy inputs, so treat mosaics as personal data under GDPR/NDPR and protect the salt and pepper accordingly.

## Quick Start

```bash
# Clone
git clone https://github.com/papoveB01/EdgeGW_Project.git
cd EdgeGW_Project

# Run tests
make test

# Build binary
make build

# Run locally (set env vars first)
cp .env.example .env
# Edit .env with your Hub credentials
make run

# Or with Docker
make docker
make docker-run
```

## Anonymization Pipeline

| Raw PII Field | Anonymized Output | Method |
|---------------|-------------------|--------|
| National ID (BVN/NIN) | `identity_mosaic` (scope `global`) | HMAC-SHA256(key=regional_pepper, "v2\|id\|" + normalized national_id) |
| Customer ID + Name (fallback) | `identity_mosaic` (scope `local`) | HMAC-SHA256(key=bank_salt\|pepper, "v2\|local\|" + normalized id\|name) |
| Transaction Amount | `amount_tier` | TIER_1 (≤$500), TIER_2 ($500–2.5K), TIER_3 ($2.5K–10K), TIER_4 (>$10K) |
| Lat/Long (optional) | `location_zone` | Geohash precision 5 (~4.9km grid cells); `ZONE_UNKNOWN` when absent |
| Timestamp | Bucketed timestamp | RFC 3339, normalized to UTC, rounded down to 15-minute windows |
| Account Number | `account_hash` | SHA-256(account \| bank_salt) |
| Device ID | `device_id_hash` | SHA-256(device_id \| bank_salt) |
| IP Address | `ip_hash` | SHA-256(ip \| bank_salt) |
| Counterparty National ID | `destination_mosaic` (scope `global`) | Same derivation as global identity mosaic |
| Counterparty ID (fallback) | `destination_mosaic` (scope `local`) | HMAC-SHA256(key=bank_salt\|pepper, "v2\|local\|" + normalized counterparty_id) |

### Mosaic scopes (v2)

Every signal carries `mosaic_scope` and `mosaic_version` so the Hub knows what it can match:

- **`global`** — derived from a canonical national identifier (BVN/NIN) keyed *only* with the shared `REGIONAL_PEPPER`. The same person produces the same mosaic at every member bank, enabling cross-institutional pattern detection. Identifiers are normalized (case, whitespace, dashes) before hashing, and the global destination-mosaic derivation matches the identity derivation — so mule-route hops link up.
- **`local`** — fallback when no national ID is supplied. Keyed with the bank salt as well, so it's stable within one institution only; the Hub should not attempt cross-bank matching on local mosaics.

Send `national_id` (and `counterparty_national_id` on transfers) whenever available — without them, signals still contribute to single-institution detection but not cross-bank correlation.

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Service health check |
| `/metrics` | GET | Operational metrics (signals processed, spool depth, failures, uptime) |
| `/process` | POST | Accept raw transaction, anonymize, deliver to Hub (requires `INBOUND_API_KEY` when set). With `SPOOL_DIR` set: persists the anonymized signal and returns **202 Accepted**; a background forwarder delivers it. Without: forwards synchronously and returns 200 (or 502 on failure). |

> A compliance `resolve-pii` endpoint (mosaic → local PII lookup) is planned but intentionally not shipped: it requires a local encrypted audit store and Hub-issued officer JWT validation, neither of which exists yet.

### POST /process

```json
{
  "id": "CUST-001",
  "name": "John Doe",
  "national_id": "22345678901",
  "account": "ACC-1234567890",
  "amount": 9500.00,
  "latitude": 6.4541,
  "longitude": 3.3947,
  "timestamp": "2026-01-15T14:07:33.000Z",
  "device_id": "DEV-MOBILE-001",
  "ip": "192.168.1.100",
  "branch_id": "LAG-01",
  "signal_type": "transaction",
  "endpoint_type": "MOBILE_APP",
  "counterparty_id": "CUST-999"
}
```

Required fields: `id`, `name`, `account`, `amount` (> 0), `timestamp` (RFC 3339 with timezone offset, e.g. `2026-01-15T14:07:33Z`)

Optional fields: `national_id` (BVN/NIN — enables cross-bank matching), `latitude`/`longitude` (must be provided together; omit for card-not-present transactions → `ZONE_UNKNOWN`), `device_id`, `ip`, `branch_id`, `signal_type`, `endpoint_type`, `counterparty_id`, `counterparty_national_id`

## Configuration

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `INSTITUTION_ID` | Yes | Your institution ID from Hub onboarding |
| `API_KEY` | Yes | API key from Hub onboarding |
| `HMAC_SECRET` | Yes | HMAC signing secret from Hub onboarding |
| `HUB_API_URL` | Yes | Hub signal endpoint URL |
| `BANK_SALT` | Yes | Local salt for hashing (min 32 chars, never shared) |
| `REGIONAL_PEPPER` | Yes | Shared pepper from Hub — the HMAC key for global mosaics (enables cross-bank matching) |
| `SPOOL_DIR` | Recommended | Durable queue directory; enables async 202 mode so Hub outages don't lose signals (Docker default: `/spool`) |
| `SPOOL_MAX_DEPTH` | No | Max queued signals before /process returns 503 (default: 10000) |
| `GATEWAY_PORT` | No | Server port (default: 8080) |
| `REPORTING_THRESHOLD` | No | AML reporting limit (default: 10000) |
| `CONFIG_PATH` | No | Path to config JSON file (default: /config/gateway.json) |
| `INBOUND_API_KEY` | Recommended | Key core banking systems must present on `/process` (`Authorization: Bearer` or `X-Gateway-API-Key`) |
| `TLS_CERT_FILE` / `TLS_KEY_FILE` | Recommended | Serve HTTPS; without them raw PII transits the bank network unencrypted |

### Config File

Environment variables take precedence. The config file provides defaults:

```bash
cp deployments/config/gateway.example.json deployments/config/gateway.json
# Edit with your values
```

## Hub Authentication

The gateway authenticates to the Hub using a 3-point handshake:

1. **API Key** — `Authorization: Bearer <API_KEY>` header
2. **HMAC Signature** — `X-Intel-Signature: HMAC-SHA256(payload, HMAC_SECRET)` header
3. **Hub validates** institution is active and within rate limits

## Security Features

- **Distroless container** — no shell, no package manager, nonroot user
- **No raw PII transmission** — all personal data pseudonymized before leaving the bank
- **Inbound authentication** — `/process` requires `INBOUND_API_KEY` (constant-time compare)
- **TLS listener** — set `TLS_CERT_FILE`/`TLS_KEY_FILE`
- **HMAC-SHA256 payload signing** — tamper-proof signal integrity
- **Strict input validation** — RFC 3339 timestamps, positive amounts, coordinate ranges, non-empty identifiers
- **Request body size limit** — 1MB max to prevent OOM attacks
- **Structured JSON logging** — no PII in logs
- **Graceful shutdown** — in-flight requests drain on SIGINT/SIGTERM (15s budget)
- **Durable spool** — anonymized signals (never raw PII) persist to disk before acknowledgment; delivery survives Hub outages and gateway restarts, with dead-lettering for permanently rejected signals
- **Bounded retry with exponential backoff** — 4xx Hub errors are not retried; in synchronous mode the full retry budget (~8.25s) fits inside the 10s write timeout; client cancellation stops retries

## Development

```bash
# Run tests with race detector
make test

# Generate coverage report
make test-cover

# Lint
make lint

# Build and run
make build && ./edge-gateway
```

## Project Structure

```
EdgeGW_Project/
  cmd/gateway/          # Application entry point
    main.go
  internal/
    adapters/           # Inbound request parsing, Hub forwarding, metrics
    config/             # Configuration loading (env + file)
    middleware/          # Request logging, body size limit
    processor/          # Core anonymization logic + tests
  deployments/          # Docker Compose + config templates
  scripts/              # Integration test scripts
  .github/workflows/    # CI pipeline
```

## Contributing

Edge Gateway is developed in the open and contributions are welcome. Please
read [CONTRIBUTING.md](CONTRIBUTING.md) first — all commits must be signed off
under the [Developer Certificate of Origin](DCO) (`git commit -s`). By
contributing you agree your work is licensed to the project under Apache 2.0;
you keep the copyright to your contribution.

- Bugs and features: open a GitHub issue.
- Security vulnerabilities: **do not** file a public issue — follow
  [SECURITY.md](SECURITY.md).
- Community standards: [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## License

Copyright 2026 IntelFraud.

The Edge Gateway source code is licensed under the **Apache License 2.0** — see
[LICENSE](LICENSE) and [NOTICE](NOTICE). You may use, modify, and redistribute
it under those terms.

The name "IntelFraud", "Edge Gateway", and associated logos are trademarks and
are **not** covered by the code license — see [TRADEMARKS.md](TRADEMARKS.md).
The IntelFraud Hub service is a separate, proprietary component and is not part
of this repository.
