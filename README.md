# IntelFraud Edge Gateway

The Privacy Wall - A hardened microservice that ensures PII never leaves your network.

## Quick Start

### Prerequisites

- Docker and Docker Compose
- Go 1.21+ (for local development)

### Running with Docker Compose

The Edge Gateway is included in the main `docker-compose.yml`. To start it:

```bash
docker compose up edge-gateway
```

### Configuration: Hub vs Local

**A. Parameters provided by the Hub UI** (or downloaded via "Download Configuration"):

- `institution_id` (env: `INSTITUTION_ID`) – e.g. BNK_001
- `api_key` (env: `API_KEY`) – Bearer token for Hub authentication
- `hub_endpoint_url` (env: `HUB_API_URL`) – where to send anonymized signals

**B. Parameters managed locally by the bank** (never sent to Hub):

- `bank_salt` (env: `BANK_SALT`) – privacy key for anonymization (min 32 chars)
- `internal_adapter_config` (env: `INTERNAL_ADAPTER_CONFIG`, JSON string) – mapping for ATM/POS ports
- `local_log_retention` (env: `LOCAL_LOG_RETENTION_DAYS`) – audit trail retention in days (default: 90)

You can set these via environment variables or by mounting a config file (e.g. `/config/gateway.json`) and setting `CONFIG_PATH` if needed. See `config/config.example.json`.

### Environment Variables

Required (env or config file):

- `INSTITUTION_ID` / hub `institution_id`
- `API_KEY` / hub `api_key`
- `HUB_API_URL` / hub `hub_endpoint_url`
- `HMAC_SECRET` – from Hub Admin at onboarding (not stored in config file for security)
- `BANK_SALT` / local `bank_salt`
- `REGIONAL_PEPPER` – shared regional pepper from Hub (optional for dev)
- `GATEWAY_PORT` – port for the gateway (default: 8080)

Optional:

- `CONFIG_PATH` – path to JSON config file (default: `/config/gateway.json`)
- `INTERNAL_ADAPTER_CONFIG` – JSON object for ATM/POS adapter mapping
- `LOCAL_LOG_RETENTION_DAYS` – local audit log retention in days (default: 90)

### Testing

1. **Health Check:**
   ```bash
   curl http://localhost:8080/health
   ```

2. **Process Transaction:**
   ```bash
   ./test_gateway.sh
   ```

   Or manually (minimal payload):
   ```bash
   curl -X POST http://localhost:8080/process \
     -H "Content-Type: application/json" \
     -d '{
       "id": "1234567890",
       "name": "John Doe",
       "account": "ACC123456",
       "amount": 1250.00,
       "latitude": 6.5244,
       "longitude": 3.3792,
       "timestamp": "2024-02-07T12:00:00Z"
     }'
   ```

   **With fraud-detection fields** (recommended for Midnight Sweep, Credential Stuffing, Impossible Travel):
   ```bash
   curl -X POST http://localhost:8080/process \
     -H "Content-Type: application/json" \
     -d '{
       "id": "1234567890",
       "name": "John Doe",
       "account": "ACC123456",
       "amount": 1250.00,
       "latitude": 6.5244,
       "longitude": 3.3792,
       "timestamp": "2024-02-07T12:00:00Z",
       "device_id": "HW-ABC-123",
       "branch_id": "LAG-01",
       "ip": "10.0.1.5"
     }'
   ```
   - `device_id` or `device_id_hash`: enables Credential Stuffing (cross-bank) and Midnight Sweep. Gateway hashes `device_id` if provided; or pass pre-hashed `device_id_hash`.
   - `branch_id`: enables Impossible Travel (physical ATM/branch; must match Hub `branch_locations`).
   - `ip` or `ip_hash`: optional anchor for Midnight Sweep.

### Building the Docker Image

```bash
cd edge-gateway
docker build -t edge-gateway:latest .
```

### Optional request fields (fraud detection)

For full Hub fraud detection, the Core Banking System can send these optional fields in the `/process` JSON body:

| Field | Purpose | Hub use |
|-------|---------|--------|
| `device_id` | Device/hardware identifier | Hashed and sent as `metadata.device_id_hash` → Credential Stuffing (cross-bank), Midnight Sweep |
| `device_id_hash` | Pre-hashed device fingerprint | Passed through as `metadata.device_id_hash` |
| `ip` | Client IP | Hashed and sent as `metadata.ip_hash` → Midnight Sweep |
| `ip_hash` | Pre-hashed IP | Passed through as `metadata.ip_hash` |
| `branch_id` | Physical ATM/branch code (e.g. LAG-01) | Sent as `metadata.branch_id` → Impossible Travel; must exist in Hub `branch_locations` |
| `signal_type` | e.g. `transaction`, `login` | Default `transaction` |
| `endpoint_type` | e.g. `BRANCH`, `ATM`, `MOBILE` | Stored in metadata |

**Edge Gateway must reliably pass `device_fingerprint` (or `device_id_hash`) for cross-bank Credential Stuffing and Midnight Sweep.** Coordinates should reflect the physical ATM/branch location (and `branch_id` set) for Impossible Travel.

**Multi-Bank Structuring (Smurfing):** The gateway maps amounts to tiers and sets `metadata.is_near_threshold = true` when the transaction amount is within 5% of the AML reporting threshold (configurable via `reporting_threshold` in local config or `REPORTING_THRESHOLD` env, default 10000). This lets the Hub distinguish "just below" patterns (e.g. two $9.9k at different banks) from normal activity.

### Architecture

- **processor/**: Core anonymization logic (hashing, tiering, geohash); adds device_id_hash, ip_hash, branch_id to metadata when provided
- **adapters/**: Inbound (REST) and outbound (Hub communication)
- **main.go**: HTTP server and request routing

### Security Features

- Distroless Docker image (no shell, minimal attack surface)
- HMAC-SHA256 payload signing
- TLS 1.3 communication with Hub
- Zero PII leakage (all data anonymized before transmission)

### Performance

- Sub-10ms processing time
- High concurrency (Go-based)
- Stateless design (no database)


