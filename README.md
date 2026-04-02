# Edge Gateway

Privacy-preserving fraud signal gateway for financial institutions. Sits inside a bank's infrastructure, strips PII from transactions, and forwards anonymized fraud signals to the IntelFraud Hub for cross-institutional pattern detection.

## Architecture

```
Bank Core System ──POST /process──> Edge Gateway ──anonymize──> Hub API
                                         │
                                    PII stays here
                                    (never leaves bank)
```

**Zero PII leaves the bank.** The gateway replaces personally identifiable information with irreversible hashes (identity mosaics), privacy-preserving tiers, and geohash zones before forwarding to the Hub.

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
| Transaction Amount | `amount_tier` | TIER_1 (<$500), TIER_2 ($500-2.5K), TIER_3 ($2.5K-10K), TIER_4 (>$10K) |
| Lat/Long | `location_zone` | Geohash precision 5 (~4.9km grid cells) |
| Timestamp | Bucketed timestamp | 15-minute window rounding |
| Account Number | `account_hash` | SHA-256(account \| bank_salt) |
| Device ID | `device_id_hash` | SHA-256(device_id \| bank_salt) |
| IP Address | `ip_hash` | SHA-256(ip \| bank_salt) |
| Counterparty | `destination_mosaic` | SHA-256(counterparty_id \| bank_salt \| regional_pepper) |

The `identity_mosaic` uses the shared `REGIONAL_PEPPER` so the same person at different banks produces the same hash — enabling cross-bank fraud detection without exposing identity.

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Service health check |
| `/metrics` | GET | Operational metrics (signals processed, failures, uptime) |
| `/process` | POST | Accept raw transaction, anonymize, forward to Hub |
| `/resolve-pii` | POST | Map identity_mosaic back to local PII (compliance only) |

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

Required fields: `id`, `name`, `account`, `amount`, `latitude`, `longitude`, `timestamp`

Optional fraud detection fields: `device_id`, `ip`, `branch_id`, `signal_type`, `endpoint_type`, `counterparty_id`

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
- **Zero PII transmission** — all personal data hashed before leaving the bank
- **HMAC-SHA256 payload signing** — tamper-proof signal integrity
- **Request body size limit** — 1MB max to prevent OOM attacks
- **Structured JSON logging** — no PII in logs
- **Graceful shutdown** — SIGINT/SIGTERM handling
- **Retry with exponential backoff** — resilient Hub connectivity

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
