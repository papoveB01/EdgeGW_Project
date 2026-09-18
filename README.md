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

`identity_mosaic`/`destination_mosaic` keying depends on the deployment's
`MOSAIC_KEYING` setting — `bank` (default) or `regional`. See
[Mosaic scopes (v3)](#mosaic-scopes-v3) below for what that changes.

| Raw PII Field | Anonymized Output | Method (`MOSAIC_KEYING=bank`, default) | Method (`MOSAIC_KEYING=regional`) |
|---------------|-------------------|------------------------------------------|-------------------------------------|
| National ID (BVN/NIN) | `identity_mosaic` (scope `bank`/`regional`, basis `national_id`) | HMAC-SHA256(key=bank_salt[\|pepper], "v3\|id\|" + normalized national_id) | HMAC-SHA256(key=pepper, "v3\|id\|" + normalized national_id) |
| Customer ID + Name (fallback) | `identity_mosaic` (scope `bank`, basis `internal_id_fallback`) | HMAC-SHA256(key=bank_salt[\|pepper], "v3\|local\|" + normalized id\|name) | same as bank mode — fallback is always bank-scoped |
| Transaction Amount | `amount_tier` | TIER_1 (≤$500), TIER_2 ($500–2.5K), TIER_3 ($2.5K–10K), TIER_4 (>$10K) | — |
| Lat/Long (optional) | `location_zone` | Geohash precision 5 (~4.9km grid cells); `ZONE_UNKNOWN` when absent | — |
| Timestamp | Bucketed timestamp | RFC 3339, normalized to UTC, rounded down to 15-minute windows | — |
| Account Number | `account_hash` | HMAC-SHA256(key=bank_salt, "v3\|account\|" + account) | same |
| Device ID | `device_id_hash` | HMAC-SHA256(key=bank_salt, "v3\|device\|" + device_id) | same |
| IP Address | `ip_hash` | HMAC-SHA256(key=bank_salt, "v3\|ip\|" + ip) | same |
| Counterparty National ID | `destination_mosaic` (scope `bank`/`regional`, basis `national_id`) | Same derivation as the corresponding identity mosaic above | same |
| Counterparty ID (fallback) | `destination_mosaic` (scope `bank`, basis `internal_id_fallback`) | HMAC-SHA256(key=bank_salt[\|pepper], "v3\|local\|" + normalized counterparty_id) | same |

`[\|pepper]` means the pepper is folded in only when set — it's optional in
`bank` mode. See [Configuration](#environment-variables) for `MOSAIC_PEPPER`.

**Flag-day break:** this is mosaic version 3 (`mosaic_version: 3`). v3
mosaics never collide with v2 ones — the domain prefixes changed from
`"v2|..."` to `"v3|..."` and the default keying changed from "pepper alone"
to "this institution's own salt, always folded in." There is no dual
emission; see `docs/signal-schema-v2.md` for the full wire-format writeup
(the file keeps its old name for link continuity, but documents v3).

### Mosaic scopes (v3)

Every signal carries `mosaic_scope`, `mosaic_basis`, and `mosaic_version` — two independent facts, not one combined flag like the old v2 `mosaic_scope`:

- **`mosaic_scope`** — which secret keyed the mosaic, i.e. whether it's valid to compare across institutions:
  - **`bank`** (produced whenever `MOSAIC_KEYING=bank`, the default, or as the fallback basis under either setting) — keyed with this institution's own `BANK_SALT`. Never comparable to a mosaic from a different institution, regardless of what identifier produced it.
  - **`regional`** (produced only for national-ID mosaics under `MOSAIC_KEYING=regional`) — keyed on the shared pepper alone, exactly like the old global scope. Comparable across every gateway sharing that pepper. This deliberately re-introduces cross-gateway derivability (anyone holding the pepper can enumerate the national-ID space) — opt in only when that tradeoff is understood; see the `MOSAIC_KEYING` row in [Configuration](#environment-variables).
- **`mosaic_basis`** — what identifier produced the mosaic, independent of scope:
  - **`national_id`** — derived from a canonical national identifier (BVN/NIN). Stable.
  - **`internal_id_fallback`** — no national ID was supplied; falls back to a bank-internal identifier (plus name, for identity mosaics). Weaker — changes if the internal ID changes or a name is corrected. Always `mosaic_scope: "bank"`.

Send `national_id` (and `counterparty_national_id` on transfers) whenever available for the more stable `national_id` basis; without them, signals fall back to `internal_id_fallback`, which still supports single-institution detection.

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | **Liveness** only: 200 whenever this process can serve HTTP, full stop. It never inspects the spool, so a full or stale spool during a destination outage — which a restart cannot fix — still reports healthy. This is what the Docker healthcheck (and the binary's `-healthcheck` self-probe) calls, and it is the **only** one of these three endpoints safe to wire to an auto-restart action (a Kubernetes `livenessProbe`, Swarm, an autoheal sidecar, etc). |
| `/readyz` | GET | **Readiness/degradation**, not liveness: reports whether the gateway is keeping up, not just alive. Returns `503` with a `reasons` list when a registered spool is at/near capacity (see `READINESS_MAX_DEPTH_RATIO`) or its oldest pending signal has aged past a staleness threshold (see `READINESS_MAX_STALENESS_SECONDS`), when `Enqueue`'s post-rename spool-directory fsync has failed for `READINESS_MAX_SPOOL_FSYNC_FAILURES` consecutive signals (see [Durable spool](#durable-spool)), or when the egress audit log (see [Egress audit log](#egress-audit-log)) has failed to write for `READINESS_MAX_AUDIT_FAILURES` consecutive confirmed deliveries. A full or stale spool, a persistent directory-fsync failure, or a stuck audit log, during a destination outage/degraded volume is the durable queue (or the compliance record of it) working as designed, not a dead process — restarting fixes none of it, and would only add a self-inflicted `/process` outage on top. **Never wire this endpoint to an auto-restart action.** Wire it to alerting/paging, or, if used as a Kubernetes `readinessProbe`, to traffic removal only. |
| `/metrics` | GET | Operational metrics (signals processed, spool depth and age of oldest pending item, delivery failures and latency, uptime). Because egress to the destination is one-way, this and `/readyz` are the only way to tell a feed running hours behind from a healthy one. |
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

### Deployment modes

The gateway runs in one of two modes, set with `GATEWAY_MODE`:

- **`middleware`** (default, for backward compatibility) — one-way egress to an
  external vendor fraud platform (inference only; the vendor never trains on
  this data, and never sends anything back over this channel). Requires
  `HUB_API_URL`, `API_KEY`, and `HMAC_SECRET`. If any of these is missing, the
  gateway **fails fast at startup** with a clear error — it no longer silently
  starts up and POSTs to a placeholder host.
- **`standalone`** — the gateway runs independent of any external system.
  None of the vendor-facing settings above are required. Anonymized signals
  are instead written to local durable storage (newline-delimited JSON, one
  file per UTC day) under `STANDALONE_SINK_DIR`, so signals are never
  silently dropped or queued forever with nowhere to go. It has no built-in
  rotation or retention policy — old files accumulate until an operator
  archives or deletes them.

Both modes still require `INSTITUTION_ID` and `BANK_SALT`: they drive local
pseudonymization regardless of where (or whether) signals leave the bank.

Separately from `GATEWAY_MODE`, **`MOSAIC_KEYING`** (`bank`, the default, or
`regional`) controls how `identity_mosaic`/`destination_mosaic` are keyed —
see [Mosaic scopes (v3)](#mosaic-scopes-v3). It applies in both `middleware`
and `standalone` mode.

**Pepper requirement now follows `MOSAIC_KEYING`, not `GATEWAY_MODE`:** in
the default `bank` keying mode, every mosaic already folds in this
institution's own `BANK_SALT` (`mosaicKeyMaterial(BANK_SALT, pepper)`), so
`MOSAIC_PEPPER`/`REGIONAL_PEPPER` is **optional** — in both `middleware` and
`standalone` mode. If set, it's folded in as additional key material
(defense in depth); if unset, the key is `BANK_SALT` alone, which is a full
HMAC key, never an empty one. In `regional` keying mode, the pepper is
**required** — the gateway fails fast at startup if it's unset, since that
mode's national-ID mosaics are keyed on the pepper *alone* and an
HMAC keyed with an empty string is a publicly computable function with no
secret in it (and a national ID is only an 11-digit space — trivially
enumerable offline). This replaces the old standalone-only
"derive-a-local-pepper-from-BANK_SALT" behavior, which existed only because
v2's global mosaic had no bank-salt fallback to begin with.

### Durable spool

Set `SPOOL_DIR` to enable the async delivery path: `/process` persists the
anonymized signal to disk and returns **202 Accepted** before a background
forwarder delivers it, so an outage of the destination (vendor platform, or
a full/unwritable standalone sink) doesn't lose signals or block the core
banking system.

**What the 202 promises.** By default (`SPOOL_FSYNC` unset, or anything
other than `false`), `Enqueue` fsyncs the signal's temp file before renaming
it into place, then fsyncs the spool directory after the rename — so the
202 means the signal survives a **host power loss**, not just a process
crash (a plain process crash never loses anything either way, since the OS
page cache holding the unsynced write survives it; fsync exists for the
case where the *machine* goes down, not just the gateway process). If
either fsync fails, `Enqueue` returns an error instead of reporting the
signal queued, so `/process` returns a failure status rather than a 202 it
can't back up; see `internal/spool.Enqueue`'s doc comment for exactly how
each failure point is handled (and why a directory-fsync failure, unlike
the earlier failure points, deliberately leaves the already-committed file
in place rather than discarding it).

**The cost, measured.** An fsync per signal puts a disk sync on `/process`'s
hot path. Measured with `go test -bench BenchmarkEnqueue ./internal/spool/`
on the development machine (Apple M3 Pro, macOS — see the caveat below):

| | latency/op | implied throughput ceiling |
|---|---|---|
| `SPOOL_FSYNC` on (default), serial | ~6.7 ms | ~150 ops/sec |
| `SPOOL_FSYNC` on (default), parallel callers | ~3.9 ms | ~250 ops/sec |
| `SPOOL_FSYNC=false` | ~0.12–0.15 ms | ~7,000–8,000 ops/sec |

Fsync is roughly 40–55x slower than skipping it — expected, since it's a
disk sync rather than a page-cache write. Against this repo's own estimate
of ~23 tx/sec average with peaks several times that for a mid-size retail
bank, the default's ceiling (~150–250 ops/sec on this machine) clears that
bar but without a huge margin, and it is a genuine tradeoff, not a free
lunch — see the PR that introduced this measurement (closes #13) for the
full discussion. **Caveat:** these numbers were taken on macOS, where Go's
`os.File.Sync` issues `F_FULLFSYNC` (a full drive cache flush, stronger and
slower than a bare POSIX fsync). This project's production target is Linux
(see the Dockerfile), where a plain fsync — especially against a disk with
a battery-backed or otherwise safe write cache — is typically substantially
faster. Operators should re-run `BenchmarkEnqueue` against their own
production storage before relying on either number.

**Opting out.** `SPOOL_FSYNC=false` skips both fsyncs. Only set this if you
have measured your own hardware and deliberately accepted the risk: with it
set, a 202 means the signal is queued in a way that survives a *process*
crash (gateway restart, container recreation) but **not** a *host* power
loss or hard reset — a crash at the wrong moment can lose signals the core
banking system was already told were durably queued, with no trace
anywhere (the spool file is gone, and the egress audit log only records
confirmed deliveries — see [Egress audit log](#egress-audit-log)). Don't
disable this to work around a slow disk without understanding that
consequence.

**A persistent directory-fsync failure is a degraded state, not a data-loss
one — and `/readyz` says so.** A *transient* directory-fsync failure is the
case above: the signal's file already has its final name and fsynced
contents, so nothing is rolled back, `Enqueue` still returns an error (the
202 promise genuinely isn't true yet), and the background forwarder
delivers the signal anyway. On a *degraded* volume that keeps permitting
writes and renames but not directory metadata syncs (plausible on some
network or cluster filesystems), that same failure repeats on every
subsequent `Enqueue` — every signal keeps queuing and delivering correctly,
but every request gets a spurious `500` instead of `202`, and a core
banking system that retries on `500` would produce an unbounded stream of
duplicate signals to the vendor for a condition that isn't losing any
data. Rather than only ever surface that as an error-per-request, the spool
tracks consecutive directory-fsync failures (resetting to 0 the moment one
succeeds again) and exposes it two ways: the `spool_dir_fsync_failures`
counter on `/metrics` (every occurrence, mirroring `audit_write_failures`),
and, once `READINESS_MAX_SPOOL_FSYNC_FAILURES` consecutive failures are
reached (default: 3), a distinct `/readyz` reason — the same escalation
shape `READINESS_MAX_AUDIT_FAILURES` already gives a stuck egress audit
log. As with every other `/readyz` condition, **do not wire this to an
auto-restart action** — see [API Endpoints](#api-endpoints).

### Egress audit log

Neither the spool nor `/metrics` can answer "show me everything you sent
this vendor last quarter": the spool deletes a signal's file the instant
delivery succeeds (its on-disk state is evidence of what hasn't been
delivered yet, never of what was), and `/metrics` counters are in-memory,
reset on restart, and carry no per-signal identity.

Set `EGRESS_AUDIT_DIR` to enable a separate, durable, append-only record of
every CONFIRMED delivery (vendor-accepted in middleware mode, durably
written to the local sink in standalone mode) — never of an attempt or an
enqueue. Records are newline-delimited JSON, one file per UTC day (same
convention as the standalone sink), fsynced before being reported as
written, and contain the delivery timestamp, the destination, `signal_id`,
`mosaic_version`, `feature_version`, `mosaic_scope`, `mosaic_basis` (see
[Mosaic scopes (v3)](#mosaic-scopes-v3) — scope and basis are orthogonal, so
the audit record carries both rather than silently dropping one), and a
SHA-256 digest of the exact delivered payload bytes — proof of what was
sent without necessarily keeping a second copy of it. The full payload is
stored only if
`EGRESS_AUDIT_STORE_PAYLOAD=true` is set explicitly; the default is
digest-only, because the payload is pseudonymized but still personal data,
and a second copy is a second liability. Audit files are written `0o600`
under a `0o700` directory.

**Startup writability check.** `EGRESS_AUDIT_DIR` is not just `mkdir -p`'d: the
gateway writes, fsyncs and removes a small probe file in it before starting,
so a read-only mount or wrong permissions fail loudly at boot — the same as
every other required setting — instead of at the first confirmed delivery,
by which point the destination has already accepted the signal.

**If the audit write fails immediately after the destination has already
accepted a signal**, the gateway reports failure rather than success. In
spool mode the signal stays queued and is retried; in synchronous mode,
whatever calls `/process` may retry it. Either way this can cause the
destination to receive a duplicate delivery. This is deliberate: for a
compliance control, a duplicate delivery is a nuisance, but a signal that
left the bank with no durable record of it is a silent gap in what an
auditor can be shown.

**Bounding the duplicate stream.** A naive retry would re-POST the same
signal to the destination on every spool retry — roughly every 30 seconds,
indefinitely, for as long as the audit directory stays broken. For a vendor
computing velocity/count features, that doesn't just waste calls, it
corrupts their inference. The spool-mode wrapper avoids this: once a signal
has been confirmed delivered, further retries caused only by the audit
write failing do NOT redeliver it — they retry the audit write alone. The
only remaining duplicate is a genuine process restart while stuck in that
state (the in-memory "already delivered" marker doesn't survive it), which
redelivers at most once more, not once every 30 seconds forever.

**Escalation.** Watch the `audit_write_failures` counter on `/metrics` for
every failed write. In addition, after `READINESS_MAX_AUDIT_FAILURES`
consecutive audit-write failures (default: 3) on either delivery path,
`/readyz` reports unhealthy with a distinct reason — this is synchronous
mode's only automatic degradation signal, since it has no equivalent of the
spool's own staleness check (every request there just gets a 502 after a
delivery that already succeeded). As with spool degradation, **do not wire
this to an auto-restart action** — see [API Endpoints](#api-endpoints).

`EGRESS_AUDIT_DIR` is unset by default — audit logging is off, with a loud
startup warning, mirroring `SPOOL_DIR`'s default-off behavior. This package
never rotates, compresses or expires records; like the standalone sink, old
files accumulate until an operator archives or deletes them.

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `GATEWAY_MODE` | No | `middleware` (default) or `standalone` — see [Deployment modes](#deployment-modes) |
| `MOSAIC_KEYING` | No | `bank` (default) or `regional` — see [Mosaic scopes (v3)](#mosaic-scopes-v3). Independent of `GATEWAY_MODE`. |
| `INSTITUTION_ID` | Yes | Your institution's own identifier; used in local pseudonymization in both modes |
| `API_KEY` | Yes, in `middleware` mode | API key for the vendor platform |
| `HMAC_SECRET` | Yes, in `middleware` mode | HMAC signing secret for the vendor platform |
| `HUB_API_URL` | Yes, in `middleware` mode | Vendor platform signal endpoint URL. There is no built-in default — an unset value fails startup instead of silently posting to a placeholder host |
| `BANK_SALT` | Yes | Local salt for hashing (min 32 chars, never shared) |
| `MOSAIC_PEPPER` | Yes, in `MOSAIC_KEYING=regional` | Additional HMAC key input for mosaics. Optional in `MOSAIC_KEYING=bank` (the default) — `BANK_SALT` alone already keys every mosaic; if set, the pepper is folded in too as defense in depth. Required, and fails startup if unset, in `MOSAIC_KEYING=regional`. `REGIONAL_PEPPER` is accepted as a backward-compatible alias (if both are set, `MOSAIC_PEPPER` wins). |
| `STANDALONE_SINK_DIR` | No | Directory for the local sink's newline-delimited JSON files in `standalone` mode (default: `./sink`; Docker default: `/sink`) |
| `SPOOL_DIR` | Recommended | Durable queue directory; enables async 202 mode so a destination outage doesn't lose signals (Docker default: `/spool`) |
| `SPOOL_MAX_DEPTH` | No | Max queued signals before /process returns 503 (default: 10000) |
| `SPOOL_FSYNC` | No | Set to `false` to skip fsyncing the spool temp file and directory on enqueue (default: `true`/on). See [Durable spool](#durable-spool) — disabling this means a 202 no longer implies a signal survives host power loss, only a process crash. |
| `EGRESS_AUDIT_DIR` | No (recommended for compliance) | Directory for the durable, append-only egress audit log (confirmed deliveries only — see [Egress audit log](#egress-audit-log)). Unset means no audit trail is written, logged loudly at startup |
| `EGRESS_AUDIT_STORE_PAYLOAD` | No | Set to `true` to store the full delivered payload alongside its digest in the audit log (default: digest-only) |
| `READINESS_MAX_DEPTH_RATIO` | No | Fraction of `SPOOL_MAX_DEPTH` at/above which `/readyz` reports unhealthy (default: `0.95`). See [API Endpoints](#api-endpoints) — this must never be wired to an auto-restart action. |
| `READINESS_MAX_STALENESS_SECONDS` | No | How old (in seconds) the oldest pending spool item may get before `/readyz` reports unhealthy (default: `900`, i.e. 15 minutes) |
| `READINESS_MAX_AUDIT_FAILURES` | No | Consecutive egress-audit-log write failures (either delivery path) before `/readyz` reports unhealthy (default: `3`). See [Egress audit log](#egress-audit-log). |
| `READINESS_MAX_SPOOL_FSYNC_FAILURES` | No | Consecutive `Enqueue` post-rename spool-directory fsync failures before `/readyz` reports unhealthy (default: `3`). See [Durable spool](#durable-spool) — this is a degraded-but-not-losing-data condition, same shape as `READINESS_MAX_AUDIT_FAILURES`. |
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
- **Durable spool** — anonymized signals (never raw PII) persist to disk, fsynced before acknowledgment by default (`SPOOL_FSYNC=false` opts out — see [Durable spool](#durable-spool)); delivery survives Hub outages and gateway restarts unconditionally, and (with fsync enabled, the default) host power loss/hard resets too, with dead-lettering for permanently rejected signals
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
    auditlog/           # Durable, append-only egress audit log (confirmed deliveries only)
    config/             # Configuration loading (env + file)
    middleware/          # Request logging, body size limit
    processor/          # Core anonymization logic + tests
    spool/              # File-backed durable delivery queue
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
