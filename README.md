# Edge Gateway

Privacy-preserving fraud signal gateway for financial institutions. Sits inside a bank's infrastructure, strips PII from transactions, and forwards anonymized fraud signals to the IntelFraud Hub for cross-institutional pattern detection.

## Architecture

```
Bank Core System ──POST /process──> Edge Gateway ──anonymize──> Hub API
                                         │
                                    PII stays here
                                    (never leaves bank)
```

**No raw PII leaves the bank.** The gateway replaces personally identifiable information with salted/peppered SHA-256 pseudonyms (identity mosaics), privacy-preserving tiers, and geohash zones before forwarding to the Hub. Note this is *pseudonymization*, not full anonymization: parties holding the salt and pepper could dictionary-attack low-entropy inputs, so treat mosaics as personal data under GDPR/NDPR and protect the salt and pepper accordingly.

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
| Customer ID + Name | `identity_mosaic` | SHA-256(id \| name \| bank_salt \| regional_pepper) |
| Transaction Amount | `amount_tier` | TIER_1 (≤$500), TIER_2 ($500–2.5K), TIER_3 ($2.5K–10K), TIER_4 (>$10K) |
| Lat/Long (optional) | `location_zone` | Geohash precision 5 (~4.9km grid cells); `ZONE_UNKNOWN` when absent |
| Timestamp | Bucketed timestamp | RFC 3339, normalized to UTC, rounded down to 15-minute windows |
| Account Number | `account_hash` | SHA-256(account \| bank_salt) |
| Device ID | `device_id_hash` | SHA-256(device_id \| bank_salt) |
| IP Address | `ip_hash` | SHA-256(ip \| bank_salt) |
| Counterparty | `destination_mosaic` | SHA-256(counterparty_id \| bank_salt \| regional_pepper) |

> **Known limitation (cross-bank matching):** the mosaic currently includes the bank-local `BANK_SALT` and the bank-internal customer ID, so the same person at two different banks produces *different* mosaics. Cross-institution matching requires keying the mosaic on a canonical identifier (e.g. BVN/NIN) with the shared pepper only — a coordinated wire-format change with the Hub that is planned but not yet implemented.

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Service health check |
| `/metrics` | GET | Operational metrics (signals processed, failures, uptime) |
| `/process` | POST | Accept raw transaction, anonymize, forward to Hub (requires `INBOUND_API_KEY` when set) |

> A compliance `resolve-pii` endpoint (mosaic → local PII lookup) is planned but intentionally not shipped: it requires a local encrypted audit store and Hub-issued officer JWT validation, neither of which exists yet.

### POST /process

```json
{
  "id": "CUST-001",
  "name": "John Doe",
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

Optional fields: `latitude`/`longitude` (must be provided together; omit for card-not-present transactions → `ZONE_UNKNOWN`), `device_id`, `ip`, `branch_id`, `signal_type`, `endpoint_type`, `counterparty_id`

## Configuration

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `INSTITUTION_ID` | Yes | Your institution ID from Hub onboarding |
| `API_KEY` | Yes | API key from Hub onboarding |
| `HMAC_SECRET` | Yes | HMAC signing secret from Hub onboarding |
| `HUB_API_URL` | Yes | Hub signal endpoint URL |
| `BANK_SALT` | Yes | Local salt for hashing (min 32 chars, never shared) |
| `REGIONAL_PEPPER` | Yes | Shared pepper from Hub (enables cross-bank matching) |
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
- **Bounded retry with exponential backoff** — 4xx Hub errors are not retried; the full retry budget (~8.25s) fits inside the 10s write timeout; client cancellation stops retries

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

## License

Proprietary. Part of the IntelFraud platform.
