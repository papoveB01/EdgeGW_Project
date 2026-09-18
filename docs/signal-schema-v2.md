# Signal Schema v2 — Hub Coordination Document

Wire format emitted by Edge Gateway v2 (mosaic version 2). This document is
for the IntelFraud Hub team: it specifies what changed from v1, what the Hub
must implement before v2 gateways roll out, and the matching rules for the
new mosaic scopes.

## Signal payload

`POST <hub_endpoint_url>` — `Content-Type: application/json`

```json
{
  "signal_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
  "institution_id": "BNK_EXAMPLE",
  "signal_type": "transaction",
  "identity_mosaic": "d433f5d2a3aedcb9…64 hex chars",
  "mosaic_scope": "global",
  "mosaic_version": 2,
  "feature_version": 1,
  "timestamp": "2026-01-15T14:00:00Z",
  "metadata": {
    "amount_tier": "TIER_3",
    "location_zone": "s14kt",
    "account_hash": "…64 hex chars",
    "device_id_hash": "…64 hex chars",
    "ip_hash": "…64 hex chars",
    "branch_id": "LAG-01",
    "endpoint_type": "MOBILE_APP",
    "is_near_threshold": true
  },
  "destination_mosaic": "…64 hex chars",
  "destination_mosaic_scope": "global"
}
```

### Headers (unchanged from v1)

| Header | Content |
|--------|---------|
| `Authorization` | `Bearer <institution API key>` |
| `X-Intel-Signature` | hex HMAC-SHA256 of the raw request body, keyed with the institution's HMAC secret |

## What changed from v1

| Change | v1 | v2 |
|--------|----|----|
| Mosaic derivation | `SHA-256(id \| name \| bank_salt \| regional_pepper)` | Keyed HMAC-SHA256, see below |
| Cross-bank matchability | Broken (bank salt in every mosaic) | Works for `mosaic_scope: "global"` |
| `mosaic_scope` | absent | **new, always present**: `"global"` or `"local"` |
| `mosaic_version` | absent | **new, always present**: `2` |
| `signal_id` | absent | **new, always present**: unique per event, see below |
| `feature_version` | absent | **new, always present**: see below |
| `signal_type` / `endpoint_type` | free-form, unvalidated | **BREAKING**: closed allowlist, case-insensitive match, canonical spelling emitted — see below |
| `destination_mosaic_scope` | absent | new, present iff `destination_mosaic` is |
| Timestamp | bucketed, timezone lost | RFC 3339, normalized to UTC, 15-min bucket |
| `location_zone` | always a geohash (0,0 fabricated when unknown) | geohash-5 or `ZONE_UNKNOWN` |

## `signal_id` — per-event correlation ID

`identity_mosaic` is stable per *person* across every transaction, so on its
own it cannot join a single event to anything. `signal_id` is unique per
*event*: either the caller-supplied `transaction_ref` from the inbound
request (trimmed; blank/whitespace-only is treated as absent), or, when not
supplied, a randomly generated UUIDv4 (`crypto/rand`, never derived from any
PII field). Consumers that need to correlate a downstream result back to a
specific transaction — e.g. a fraud-scoring result returned out-of-band by an
external system — should key that join on `signal_id`, not `identity_mosaic`.

## `feature_version` — versioned feature-shape contract

`feature_version` (currently `1`) identifies the shape of the derived,
model-facing fields inside `metadata`: `amount_tier` boundaries (500 / 2500 /
10000), the 15-minute timestamp bucket width, and the geohash precision (5)
behind `location_zone`. A consumer whose model was fit to a specific
`feature_version`'s boundaries must detect and handle a version bump before
trusting new signals — these boundaries can change independently of
`mosaic_version`, since they don't affect mosaic derivation at all.

v1 and v2 mosaics never collide meaningfully — the derivations differ — so
during migration the Hub should partition matching by `mosaic_version`
(treat absent as version 1).

## `signal_type` / `endpoint_type` — closed allowlists (BREAKING CHANGE)

**Breaking change:** the gateway now hard-rejects inbound requests whose
`signal_type` or `endpoint_type` is not on a fixed allowlist, returning
`400` from `/process` instead of accepting the signal. A core banking system
sending a value outside these lists — including a value the gateway
previously forwarded unquestioned — will start seeing `400`s from this
release onward. This exists to keep the pipeline scoped to fraud-relevant
signals rather than silently widening into general behavioural egress to a
commercial vendor; it is enforced in `RawData.Validate()`.

- **`signal_type` allowlist** (canonical spelling is lowercase):
  `transaction`, `login`, `transfer`, `authentication`.
- **`endpoint_type` allowlist** (canonical spelling is uppercase):
  `MOBILE_APP`, `ATM`, `POS`, `WEB`, `BRANCH`, `API`, `USSD`, `IVR`.
  `USSD` and `IVR` were added specifically for this deployment's market —
  USSD banking and IVR/call-centre channels are common where BVN/NIN
  identifiers apply — rather than carried over from prior repo usage.
- **Matching is case-insensitive.** `"Transaction"`, `"transaction"`, and
  `"TRANSACTION"` are all accepted as the same value; likewise
  `"mobile_app"` and `"MOBILE_APP"`.
- **The emitted value is normalized to canonical spelling**, not passed
  through as typed. Whatever casing the caller sends, the outgoing signal's
  `signal_type` and `metadata.endpoint_type` always use the allowlist's own
  spelling (lowercase for `signal_type`, uppercase for `endpoint_type`), so
  the vendor sees one consistent spelling regardless of caller casing.
- An empty `signal_type` is still accepted and defaults to `"transaction"`,
  unchanged from prior behavior. `endpoint_type` remains optional; when
  absent, `metadata.endpoint_type` is simply omitted.

Both allowlists are package-level (`processor.ValidSignalTypes`,
`processor.ValidEndpointTypes`) and intended to be extended deliberately as
new legitimate values are identified.

## Mosaic derivation (gateway-side, for reference)

Inputs are normalized first: identifiers have whitespace/dots/dashes
stripped and are uppercased; names are uppercased with whitespace collapsed.

- **Global** (canonical national identifier, e.g. BVN/NIN, was supplied):

  `identity_mosaic = HMAC-SHA256(key = REGIONAL_PEPPER, msg = "v2|id|" + normalized_national_id)`

  Deterministic across all member banks sharing the pepper. The same
  derivation is used for `destination_mosaic` when the sending bank supplies
  the counterparty's national ID — therefore **a global destination mosaic
  equals the counterparty's own global identity mosaic**, which is what
  enables mule-route following.

- **Local** (no national identifier available):

  `identity_mosaic = HMAC-SHA256(key = BANK_SALT + "|" + REGIONAL_PEPPER, msg = "v2|local|" + normalized_id + "|" + normalized_name)`

  Stable within one institution only.

## Matching rules the Hub must enforce

1. **Cross-institution correlation only on `mosaic_scope: "global"`.**
   Local mosaics from different institutions are incomparable by
   construction; matching them produces false negatives at best.
2. **Within-institution correlation** may use local mosaics, keyed by
   (`institution_id`, mosaic).
3. **Route following:** a `destination_mosaic` with scope `global` may be
   joined against `identity_mosaic` values (scope `global`) from any
   institution.
4. `account_hash`, `device_id_hash`, `ip_hash` remain bank-salted:
   within-institution signals only.

## Privacy notes for the Hub

- Mosaics are **pseudonyms, not anonymous values**. The pepper is the only
  secret protecting global mosaics from dictionary attack over the national
  ID space; guard it accordingly and plan for **pepper rotation epochs**
  (rotating the pepper invalidates longitudinal linkage across the rotation
  boundary — the Hub should version peppers if long-term matching matters).
- The gateway never transmits raw PII; the Hub must never request it.
  Compliance resolution (mosaic → PII) is designed to happen inside the
  originating bank, gated on a Hub-issued officer JWT (not yet shipped).

## Delivery semantics

- Gateways may deliver asynchronously from a durable spool: expect
  occasional bursts of backlogged signals after Hub outages, in original
  submission order per gateway, with the original (bucketed) timestamps.
- Respond `200` or `201` for accepted signals.
- Any other `4xx` (except `429`) tells the gateway the signal is
  permanently unacceptable — it will dead-letter it and not retry.
  `429` and `5xx` are treated as retryable.
