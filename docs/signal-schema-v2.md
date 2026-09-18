# Signal Schema v3 — Wire Format Reference

Wire format emitted by Edge Gateway v3 (mosaic version 3). This document used
to be framed as an "IntelFraud Hub Coordination Document" — the consortium
Hub model is superseded (see `README.md` and `CLAUDE.md`). It is now a
reference for whoever consumes gateway output: the external vendor AI
platform in `middleware` mode, or an operator reading the local
newline-delimited JSON sink in `standalone` mode. There is no more "Hub" to
coordinate matching rules with, so the old "Matching rules the Hub must
enforce" section is gone — see **Consuming `mosaic_scope` and
`mosaic_basis`** below for its replacement.

**This file still keeps the name `signal-schema-v2.md` for continuity of the
existing doc path/links; its content now documents v3.**

## FLAG-DAY BREAK: v2 → v3 is not backward compatible

**v3 mosaics never collide with v2 mosaics, by construction, and there is no
dual emission.** A gateway upgrade is a hard cutover:

- The hashed domain prefixes changed from `"v2|id|"` / `"v2|local|"` to
  `"v3|id|"` / `"v3|local|"`.
- The **default** keying changed from "pepper alone, no bank secret" to
  "this institution's own `BANK_SALT`, always folded in" (see **Mosaic
  keying: bank vs. regional** below) — even holding the exact same
  `BANK_SALT`/pepper values as before, a v3 gateway in the default mode will
  **not** reproduce any v2 mosaic for the same person.
- `mosaic_scope`'s value set changed meaning entirely: `"global"`/`"local"`
  (a statement about whether the old Hub could cross-match a signal) is
  replaced by `"bank"`/`"regional"` (a statement about which secret keyed the
  mosaic — see below). Any consumer code that branched on the string
  `"global"` will silently stop matching anything once a v3 gateway is live;
  it must be updated to check `mosaic_version` and the new scope values.
- A new `mosaic_basis` field appears (and `destination_mosaic_basis` beside
  `destination_mosaic`), carrying a fact the old scope field used to
  conflate with matchability. See **Mosaic scope vs. mosaic basis** below.
- `account_hash`, `device_id_hash`, and `ip_hash` change value even though
  their JSON shape (64-char hex) doesn't: the underlying construction moved
  from a plain salted SHA-256 to a keyed HMAC with a versioned domain tag
  (see **Hash construction change** below). Any stored/joined value against
  those fields from a pre-v3 gateway will not match a v3-produced one.

There is no migration path other than partitioning by `mosaic_version`
(consumers should already do this — see `feature_version`/`mosaic_version`
independence below) and, if both old and new data must coexist, keeping them
in separate buckets. There is no dual-emission mode — a v3 gateway never
emits a `"v2|..."`-prefixed mosaic.

**Not touched by this version bump** (deliberately decoupled — see
`internal/processor.MosaicVersion`'s doc comment):

- `feature_version` (amount tier boundaries, timestamp bucket width, geohash
  precision) — still `1`, unrelated to mosaic derivation.
- `signal_id`'s domain prefix — still `"v2|sigid|"`. `signal_id` is a
  per-event correlation ID, not a mosaic, and changing its prefix would be a
  gratuitous breaking change to idempotency keys already in use with no
  corresponding security benefit.

## Signal payload

```json
{
  "signal_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
  "institution_id": "BNK_EXAMPLE",
  "signal_type": "transaction",
  "identity_mosaic": "d433f5d2a3aedcb9…64 hex chars",
  "mosaic_scope": "bank",
  "mosaic_basis": "national_id",
  "mosaic_version": 3,
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
  "destination_mosaic_scope": "bank",
  "destination_mosaic_basis": "national_id"
}
```

### Headers (unchanged)

| Header | Content |
|--------|---------|
| `Authorization` | `Bearer <institution API key>` (middleware mode only) |
| `X-Intel-Signature` | hex HMAC-SHA256 of the raw request body, keyed with the institution's HMAC secret (middleware mode only) |

`standalone` mode writes this same JSON object, one per line, to a local
newline-delimited JSON file instead of sending it anywhere — the headers
above don't apply there.

## Mosaic keying: bank vs. regional

Set by the deployment-wide `MOSAIC_KEYING` config value (env `MOSAIC_KEYING`,
default `bank`). This is a policy choice made once per gateway, not a
per-signal one.

- **`bank`** (default): every mosaic — identity and destination, for both
  the national-ID branch and the internal-ID/name fallback branch — folds
  this institution's own `BANK_SALT` into the HMAC key. A mosaic produced
  this way is **not** reproducible by anyone who doesn't hold that
  institution's `BANK_SALT`, even if they hold the pepper. The pepper
  (`MOSAIC_PEPPER`, or its backward-compatible alias `REGIONAL_PEPPER` — see
  **Pepper naming** below) is **optional** in this mode: if set, it's folded
  in as additional key material (defense in depth — leaking `BANK_SALT`
  alone, or the pepper alone, must not be enough to reproduce a mosaic); if
  unset, the key is `BANK_SALT` alone, which is still a full HMAC key, not
  an empty one.
- **`regional`** (opt-in): mosaics derived from a canonical national ID
  (BVN/NIN) are keyed on the shared pepper **alone** — exactly the pre-v3
  scheme. Every gateway configured with the same pepper derives the same
  mosaic for the same person, with no bank-specific secret required. This
  intentionally re-introduces cross-gateway derivability: **anyone holding
  the pepper can enumerate the 11-digit BVN/NIN space and build a complete
  national-ID → mosaic table.** It exists to support a possible future
  use case (a regional entity querying via a remote gateway) — enable it
  only when that tradeoff is a deliberate, understood product decision. The
  pepper is **required** in this mode; the gateway fails fast at startup if
  it's unset (see `main.validateStartup`).
  The internal-ID/name fallback branch (no national ID available) is
  **always** bank-keyed regardless of this setting — see below.

### Mosaic scope vs. mosaic basis

v2 had one field, `mosaic_scope`, doing two jobs: "was a national ID used"
and "can the Hub cross-match this." v3 splits those into two orthogonal
fields, because they don't actually move together — a fallback mosaic is
never cross-gateway comparable no matter how the deployment is configured,
while a national-ID mosaic's comparability depends entirely on
`MOSAIC_KEYING`.

- **`mosaic_scope`** — **which secret keyed this mosaic**, i.e. whether
  cross-gateway matching is even valid for it:
  - `"bank"` — keyed with (at least) this institution's own `BANK_SALT`.
    Never comparable to a mosaic from a different institution, full stop,
    regardless of what identifier produced it.
  - `"regional"` — keyed with the shared pepper alone. Comparable across
    every gateway configured with that same pepper.
- **`mosaic_basis`** — **what identifier produced this mosaic**, independent
  of how it was keyed:
  - `"national_id"` — derived from a canonical national identifier
    (BVN/NIN). Stable: the same identifier always produces the same mosaic
    for as long as the keying material doesn't change.
  - `"internal_id_fallback"` — no national identifier was available, so the
    mosaic falls back to a bank-internal identifier (plus, for
    `identity_mosaic`, the customer's name). Weaker: it changes if the
    internal ID changes or a name gets corrected. Always `mosaic_scope:
    "bank"`, regardless of `MOSAIC_KEYING` — this fallback is inherently
    tied to one institution's own records and was never a candidate for
    cross-gateway matching in the first place.

`destination_mosaic_scope` / `destination_mosaic_basis` carry the same two
facts for `destination_mosaic`, present iff `destination_mosaic` is.

### Route following (mule-route detection)

The national-ID branch's derivation is byte-identical between
`identity_mosaic` and `destination_mosaic` — so a counterparty's destination
mosaic equals their own identity mosaic **when both were produced under the
same `MOSAIC_KEYING` policy**:

- In `bank` mode, that equality only holds **within one institution**
  (both sides keyed with the same `BANK_SALT`). Two different banks running
  `bank` mode cannot use `destination_mosaic` to follow a route across the
  institution boundary — this is the direct, intended consequence of
  removing cross-gateway derivability by default.
- In `regional` mode, the equality holds **across every gateway sharing the
  pepper**, exactly as it did pre-v3 — this is `regional` mode's whole
  reason to exist.

## Consuming `mosaic_scope` and `mosaic_basis`

This replaces the old "Matching rules the Hub must enforce" section, which
was written for a Hub component that no longer exists. Whoever consumes this
payload (the vendor platform, or an operator/analyst reading the standalone
sink) should apply the same two checks that used to be the Hub's job:

1. **Only compare two mosaics across different `institution_id` values when
   both have `mosaic_scope: "regional"`.** Comparing `"bank"`-scoped
   mosaics across institutions produces false negatives at best (they were
   never derived to match) and must not be treated as a signal either way.
2. **Within one `institution_id`, any mosaic may be compared to any other
   mosaic from that same institution**, regardless of scope — `"bank"`
   scope only restricts *cross*-institution comparison.
3. **Partition all matching by `mosaic_version`.** v2 and v3 mosaics never
   collide meaningfully (the derivations differ), so treat them as
   incomparable buckets; a consumer that still holds v1 data should treat
   an absent `mosaic_version` as version `1`.
4. `account_hash`, `device_id_hash`, `ip_hash` remain bank-salted in every
   mode (they don't participate in `MOSAIC_KEYING` at all) — within-
   institution signals only, never cross-institution.

## Hash construction change: `account_hash` / `device_id_hash` / `ip_hash`

These three `metadata` fields moved from a plain salted SHA-256 to a keyed
HMAC with an explicit versioned domain tag, matching the construction
already used for mosaics and `signal_id`:

| Field | v2 (old) | v3 (new) |
|-------|----------|----------|
| `account_hash` | `SHA-256(account \| BANK_SALT)` | `HMAC-SHA256(key = BANK_SALT, msg = "v3\|account\|" + account)` |
| `device_id_hash` | `SHA-256(device_id \| BANK_SALT)` | `HMAC-SHA256(key = BANK_SALT, msg = "v3\|device\|" + device_id)` |
| `ip_hash` | `SHA-256(ip \| BANK_SALT)` | `HMAC-SHA256(key = BANK_SALT, msg = "v3\|ip\|" + ip)` |

A plain hash over a salt-suffixed concatenation is not a keyed MAC: it's
still just `SHA-256` of a string, so an attacker who only needs the
(typically much lower-entropy) value being hashed — an account number, a
device fingerprint, an IP — can mount an offline dictionary/rainbow-table
attack against it without ever needing the salt, by hashing candidate values
with a *guessed* salt until one matches (or, if the salt itself leaks,
trivially forward-computing every candidate). A keyed HMAC does not have
this weakness. This is the same rationale documented on `HMACHash` in
`internal/processor/anonymizer.go`.

These three fields are unaffected by `MOSAIC_KEYING` — they are always
`HMACHash(BANK_SALT, ...)`, in both `bank` and `regional` mode, since they
were never candidates for cross-gateway matching in the first place (see
**Consuming `mosaic_scope` and `mosaic_basis`**, point 4).

## `signal_id` — per-event correlation ID

**Unaffected by the v2→v3 mosaic changes** — still `"v2|sigid|"`, and still
described below exactly as before this document's flag-day updates.

`identity_mosaic` is stable per *person* across every transaction, so on its
own it cannot join a single event to anything. `signal_id` is unique per
*event*, derived one of two ways:

- **No `transaction_ref` supplied:** `signal_id` is a randomly generated
  UUIDv4 (`crypto/rand`), never derived from PII.
- **`transaction_ref` supplied** (optional inbound field on the request to
  `/process`; blank/whitespace-only is treated as absent): `signal_id` is
  **derived**, never the raw value —

  `signal_id = HMAC-SHA256(key = BANK_SALT, msg = "v2|sigid|" + trimmed_transaction_ref)`

  using the same `HMACHash` helper as the mosaics above, over the **exact
  trimmed bytes** of `transaction_ref` — deliberately **not** the
  `NormalizeID` form used for national IDs elsewhere in this document.
  `NormalizeID` uppercases and strips `-`/`.` so inconsistently-formatted
  national IDs converge onto one mosaic; a caller-supplied transaction
  reference needs the opposite property, since two distinct references must
  never collide onto the same `signal_id`. **`transaction_ref` is therefore
  case-sensitive and punctuation-sensitive: `"TX-001"`, `"TX.001"`,
  `"tx001"`, and `"TX001"` are four different references and derive four
  different `signal_id` values.**

  **The raw `transaction_ref` is never forwarded to the vendor.** This
  matters because `transaction_ref` accepts a fairly permissive opaque-token
  shape (see below) that a bare BVN/NIN, NUBAN account number, or phone
  number can satisfy just as easily as a real reference ID — deriving
  `signal_id` via HMAC keeps that value from ever reaching the vendor in
  recoverable form, while staying **deterministic**: the same exact
  `transaction_ref` always produces the same `signal_id` (so it still works
  as an idempotency key), and the originating bank — which holds
  `BANK_SALT` — can recompute the same HMAC over its own transaction
  references (byte-for-byte, no normalization) to join an out-of-band
  vendor result back to a transaction. The vendor, without `BANK_SALT`,
  cannot invert it or correlate references across institutions.

Consumers that need to correlate a downstream result back to a specific
transaction — e.g. a fraud-scoring result returned out-of-band by an
external system — should key that join on `signal_id` (recomputed from their
own `transaction_ref`, if they supplied one), not `identity_mosaic`.

### `transaction_ref` input shape

The inbound `transaction_ref` field must match `^[A-Za-z0-9_-]{1,64}$`
(alphanumeric, underscore, hyphen; 1–64 characters after trimming
whitespace). A `transaction_ref` value outside that shape gets `400` from
`/process`. Note this shape check is input hygiene, not the PII boundary:
the boundary is that `signal_id` is always derived from `transaction_ref`
(see above), never the raw value forwarded as-is.

**`transaction_ref` is case-sensitive and punctuation-sensitive.** It is
hashed as exact trimmed bytes (not normalized like national IDs elsewhere
in this document), so `"TX-001"`, `"TX.001"`, `"tx001"`, and `"TX001"` are
four distinct references that derive four distinct `signal_id` values.
Integrators should pick one consistent format per reference and send it
exactly that way every time — do not rely on the gateway to reconcile
formatting variants of what a human would consider "the same" reference.

## `feature_version` — versioned feature-shape contract

**Unaffected by the v2→v3 mosaic changes.** `feature_version` (currently
`1`) identifies the shape of the derived, model-facing fields inside
`metadata`: `amount_tier` boundaries (500 / 2500 / 10000), the 15-minute
timestamp bucket width, and the geohash precision (5) behind
`location_zone`. A consumer whose model was fit to a specific
`feature_version`'s boundaries must detect and handle a version bump before
trusting new signals — these boundaries can change independently of
`mosaic_version`, since they don't affect mosaic derivation at all, and vice
versa (this v2→v3 mosaic change did not touch `feature_version`).

## `signal_type` / `endpoint_type` — closed allowlists

**Unaffected by the v2→v3 mosaic changes.** The gateway hard-rejects inbound
requests whose `signal_type` or `endpoint_type` is not on a fixed allowlist,
returning `400` from `/process` instead of accepting the signal. This exists
to keep the pipeline scoped to fraud-relevant signals rather than silently
widening into general behavioural egress to a commercial vendor; it is
enforced in `RawData.Validate()`.

- **`signal_type` allowlist** (canonical spelling is lowercase):
  `transaction`, `login`, `transfer`, `authentication`.
- **`endpoint_type` allowlist** (canonical spelling is uppercase):
  `MOBILE_APP`, `ATM`, `POS`, `WEB`, `BRANCH`, `API`, `USSD`, `IVR`.
  `USSD` and `IVR` were added specifically for this deployment's market —
  USSD banking and IVR/call-centre channels are common where BVN/NIN
  identifiers apply.
- **Matching is case-insensitive.** `"Transaction"`, `"transaction"`, and
  `"TRANSACTION"` are all accepted as the same value; likewise
  `"mobile_app"` and `"MOBILE_APP"`.
- **The emitted value is normalized to canonical spelling**, not passed
  through as typed. Whatever casing the caller sends, the outgoing signal's
  `signal_type` and `metadata.endpoint_type` always use the allowlist's own
  spelling (lowercase for `signal_type`, uppercase for `endpoint_type`), so
  the vendor sees one consistent spelling regardless of caller casing.
- An empty `signal_type` is still accepted and defaults to `"transaction"`.
  `endpoint_type` remains optional; when absent, `metadata.endpoint_type` is
  simply omitted.

Both allowlists are package-level (`processor.ValidSignalTypes`,
`processor.ValidEndpointTypes`) and intended to be extended deliberately as
new legitimate values are identified.

## Mosaic derivation formulas (gateway-side, for reference)

Inputs are normalized first: identifiers have whitespace/dots/dashes
stripped and are uppercased (`NormalizeID`); names are uppercased with
whitespace collapsed (`NormalizeName`).

`mosaicKeyMaterial(salt, pepper)` is `salt` alone when `pepper == ""`, else
`salt + "|" + pepper`.

- **National ID present, `MOSAIC_KEYING=bank`** (default):

  `identity_mosaic = HMAC-SHA256(key = mosaicKeyMaterial(BANK_SALT, pepper), msg = "v3|id|" + normalized_national_id)`

  `mosaic_scope = "bank"`, `mosaic_basis = "national_id"`.

- **National ID present, `MOSAIC_KEYING=regional`:**

  `identity_mosaic = HMAC-SHA256(key = pepper, msg = "v3|id|" + normalized_national_id)`

  `mosaic_scope = "regional"`, `mosaic_basis = "national_id"`. Deterministic
  across every gateway sharing the pepper, exactly like the pre-v3 scheme.

- **No national ID (internal ID + name fallback), any `MOSAIC_KEYING`:**

  `identity_mosaic = HMAC-SHA256(key = mosaicKeyMaterial(BANK_SALT, pepper), msg = "v3|local|" + normalized_id + "|" + normalized_name)`

  `mosaic_scope = "bank"`, `mosaic_basis = "internal_id_fallback"`. Stable
  within one institution only, regardless of `MOSAIC_KEYING`.

`destination_mosaic` uses the same two formulas (national-ID branch keyed
identically to `identity_mosaic`'s; fallback branch over
`normalized_counterparty_id` alone, no name) with matching
`destination_mosaic_scope` / `destination_mosaic_basis` values.

### Pepper naming

The env var is `MOSAIC_PEPPER`. `REGIONAL_PEPPER` is accepted as a
backward-compatible alias (if both are set, `MOSAIC_PEPPER` wins) — the
rename exists because "regional" stopped accurately describing the pepper's
role once it became optional, bank-mode-only *additional* key material
rather than the sole key for a mosaic meant to match across an entire
region.

## Privacy notes

- Mosaics are **pseudonyms, not anonymous values**. In `regional` mode, the
  pepper is the only secret protecting national-ID mosaics from dictionary
  attack over the 11-digit BVN/NIN space — guard it accordingly, and plan
  for **pepper rotation epochs** (rotating the pepper invalidates
  longitudinal linkage across the rotation boundary). In `bank` mode
  (default), `BANK_SALT` plays that role instead, and is required at
  startup in every mode — see `README.md`'s Configuration section.
- The gateway never transmits raw PII to the vendor platform (middleware
  mode) or writes it to the local sink (standalone mode).
- Compliance resolution (mosaic → PII) is designed to happen inside the
  originating bank only, using records the bank already holds locally — no
  external system should ever need to request raw PII back from a gateway.

## Delivery semantics (middleware mode)

- Gateways may deliver asynchronously from a durable spool: expect
  occasional bursts of backlogged signals after destination outages, in
  original submission order per gateway, with the original (bucketed)
  timestamps.
- Respond `200` or `201` for accepted signals.
- Any other `4xx` (except `429`) tells the gateway the signal is
  permanently unacceptable — it will dead-letter it and not retry.
  `429` and `5xx` are treated as retryable.
