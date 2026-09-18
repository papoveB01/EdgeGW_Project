# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Working model: coordinator and spokes

Claude acts as **coordinator on this project and does not write code directly.**

1. **Decompose and assign.** Break the task into units and dispatch each to a
   spoke subagent running Sonnet (`Agent` with `model: "sonnet"`). Independent
   units go out in a single message so they run in parallel.
2. **Review is separate from authorship.** Assign a different subagent to review
   each PR or diff. A spoke never reviews its own work.
3. **Check confidence.** Adjudicate the review; send the unit back to a spoke if
   the result isn't convincing. Verify claims against the code rather than
   accepting an agent's report at face value.
4. **Merge** once satisfied.

This applies even to one-line changes. The coordinator's own output is
decomposition, assignment, adjudication, and the merge decision — plus reading
code as needed to plan and to verify.

## Commands

```bash
make test        # go test -v -race ./...
make lint        # go vet ./...
make build       # CGO_ENABLED=0 build -> ./edge-gateway
make test-cover  # coverage.out + coverage.html
make run         # go run ./cmd/gateway (needs env vars, see below)
make docker      # build image; make docker-run starts it with test credentials
```

Single test / single package:

```bash
go test -race -run TestAnonymizeSignal_BankKeyingMosaicDiffersAcrossBanks ./internal/processor/
go test -race ./internal/spool/
```

`scripts/test_gateway.sh [url]` is a curl-based integration smoke test against a
running gateway (defaults to `http://localhost:8080`).

CI (`.github/workflows/ci.yml`) runs vet, race tests with coverage, a build, and
a Docker build on Go 1.24. Match that toolchain version.

Minimum env to run locally (default `GATEWAY_MODE=middleware`):
`INSTITUTION_ID`, `API_KEY`, `HMAC_SECRET`, `HUB_API_URL`, `BANK_SALT` —
`main` exits 1 if any of those is missing (`GATEWAY_MODE=standalone` needs
neither `API_KEY`/`HMAC_SECRET`/`HUB_API_URL`, just `INSTITUTION_ID`/
`BANK_SALT`). `MOSAIC_PEPPER` (or its backward-compatible alias
`REGIONAL_PEPPER`) is only required when `MOSAIC_KEYING=regional`; it's
optional in the default `MOSAIC_KEYING=bank`.
`HUB_API_URL` genuinely has no built-in default and is genuinely enforced:
`config.Load()` deliberately leaves `HubEndpointURL` empty rather than
substituting a placeholder (see the doc comment on that in
`internal/config/config.go`), and `validateStartup` in `main.go` rejects an
unset value in middleware mode — `TestLoad_DefaultsWithoutFile` and
`TestValidateStartup_MiddlewareFailsFastWithoutDestination` both assert
this. (An earlier version of this file claimed the opposite — that the
check was dead code and a gateway would silently POST to a placeholder
host — but that was fixed before this repo's mosaic-v3 rekey landed;
double-check current behavior against the code rather than assuming this
paragraph stays accurate indefinitely.)

Nothing loads `.env` — `make run` is a bare `go run`, and there is no dotenv
dependency. Export the vars into your shell yourself. Add `SPOOL_DIR` to
exercise async mode.

## Primary use case (current) — read this before changing the wire contract

**The consortium IntelFraud Hub model is superseded.** Two deployment modes:

- **Middleware** — between a bank's core systems and an **external vendor's AI
  fraud platform**, one bank to one/few vendors. The vendor runs **inference
  only; no model training happens on this data.** Egress is **one-way**: the
  gateway ships signals out and never receives a score back. Vendor results
  reach the bank through a separate channel outside this system.
- **Standalone** — the gateway runs independent of any external system.

As of the mosaic v3 rekey (`MosaicVersion = 3`), the code has been brought in
line with this consortium-superseded reality:

- Mosaic keying is now bank-scoped by default (`MOSAIC_KEYING=bank`):
  `BANK_SALT` is always folded into the HMAC key, so a mosaic is not
  reproducible by anyone lacking this institution's own secret. The old
  pepper-alone derivation (deliberately excluding `BANK_SALT`, so any holder
  of the pepper could derive the same pseudonym for the same BVN/NIN) is
  retained ONLY as an explicit opt-in (`MOSAIC_KEYING=regional`), for a
  possible future use case where a regional entity queries via a remote
  gateway. `MOSAIC_PEPPER` (env alias: `REGIONAL_PEPPER`) is optional in bank
  mode and required (fails startup if unset) in regional mode.
- `mosaic_scope` no longer means "may the Hub cross-match this" (there is no
  Hub). It now means "which secret keyed this mosaic" — `"bank"` or
  `"regional"` — i.e. whether cross-gateway comparison is valid at all. A
  new, orthogonal `mosaic_basis` field (`"national_id"` or
  `"internal_id_fallback"`) carries what the old field used to conflate with
  matchability: whether the entity key came from a canonical national ID
  (stable) or a name+internal-ID fallback (weaker). See
  `internal/processor/anonymizer.go`'s `ScopeBank`/`ScopeRegional`/
  `BasisNationalID`/`BasisInternalIDFallback` doc comments and
  `docs/signal-schema-v2.md` (documents v3 despite the filename).
- `account_hash`/`device_id_hash`/`ip_hash` moved from plain
  `SHA-256(value+"|"+salt)` to keyed `HMACHash(salt, "v3|<field>|"+value)`,
  matching the construction mosaics and `signal_id` already used.
- `docs/signal-schema-v2.md`'s "Matching rules the Hub must enforce" section
  — a Hub artifact — has been replaced with consumer-facing guidance on
  `mosaic_scope`/`mosaic_basis` (see **Consuming `mosaic_scope` and
  `mosaic_basis`** in that doc).

Still open (not yet applied):

- No per-event correlation ID existed before `signal_id` was added
  (`identity_mosaic` is per-person, stable across transactions) — that gap is
  closed (see `signal_id` in `docs/signal-schema-v2.md`), but is flagged here
  because it's the same kind of "consortium code hasn't caught up yet" issue
  the mosaic rekey just addressed for keying.
- Because the vendor does **not** train, the feature transformations here
  (4 amount tiers, 15-minute buckets, geohash-5) must match whatever the
  vendor's already-trained model expects. That is a contract to verify, not a
  gateway-side choice. Labels/outcome feedback are NOT needed.

Treat any remaining Hub framing in README.md as historical/contextual — it
should already read as "vendor platform" for anything wire-format-relevant;
flag it for a fix if you find a stale spot.

## Architecture

A single Go binary that sits inside a bank, strips PII from transactions, and
forwards pseudonymized "signals" to a single configured destination. Request
path:

```
core banking --POST /process--> middleware --> adapters.ProcessInboundRequest
   --> processor.AnonymizeSignal --> spool.Enqueue (202)  OR  adapters.ForwardToHubWithRetry (200)
                                          |
                                   spool.Run (background) --> adapters.ForwardPayload --> vendor platform
```

**Stdlib only.** `go.sum` is empty and there are no third-party dependencies —
geohashing, the spool, and metrics are all hand-rolled. Adding a dependency is a
deliberate decision, not a routine one.

### Two delivery modes

`processTransaction` in `cmd/gateway/main.go` branches on whether a spool exists:

- **`SPOOL_DIR` set (async, recommended):** the anonymized signal is persisted to
  disk, `/process` returns **202**, and `spool.Run` delivers it in the background.
  Destination outages neither lose signals nor block the core banking system.
- **unset (sync):** forwards inline with bounded retry, returns **200** or **502**.

Both modes must stay in sync when changing response shape or metrics.

### Mosaic derivation is the product (`internal/processor`)

`AnonymizeSignal` is a pure function; all crypto decisions live there. Its
`keying` parameter (`KeyingBank` default / `KeyingRegional` opt-in) is a
straight pass-through of `config.GatewayConfig.MosaicKeying` — do not
hardcode a keying mode inside `AnonymizeSignal` or `processTransaction`.

`AnonymizeSignal` takes a `fallbackSignalID string` parameter rather than
generating a random `signal_id` itself — it never touches OS entropy, so it
stays genuinely pure (same inputs, including `fallbackSignalID`, always
produce the same output) even on the no-`transaction_ref` path. The caller
(`processTransaction` in `cmd/gateway/main.go`) generates that ID with
`processor.NewSignalID()` *before* calling `AnonymizeSignal`, only when
`RawData.TransactionRef` is absent, and handles a `crypto/rand` failure
there the same way every other failure branch in `processTransaction` does:
`slog.Error` (no PII), `adapters.RecordMetric("signal_id_generation_failures", 1)`,
and `http.Error(..., http.StatusInternalServerError)` — see
`genSignalID` in `main.go` (a swappable package var wrapping
`processor.NewSignalID`, so tests can inject a failing entropy source).
`NewSignalID` itself returns `(string, error)` rather than panicking; it
used to panic on `crypto/rand.Read` failure, which `net/http` recovered
per-connection with no log line, no metric, and no HTTP status — see
https://github.com/papoveB01/EdgeGW_Project/issues/4.

"Is `transaction_ref` absent" (blank/whitespace-only counts as absent) has
exactly one definition: `processor.NeedsFallbackSignalID`. Both
`processTransaction` (deciding whether to call `genSignalID` at all) and
`AnonymizeSignal` (deciding which `signal_id` branch to take) call it —
don't reintroduce a second, independent `strings.TrimSpace(ref) == ""`
check in either place, or the two can silently drift apart. If
`AnonymizeSignal` is ever called with `NeedsFallbackSignalID` true and a
blank `fallbackSignalID` anyway (a contract violation `processTransaction`
itself can't produce, but a future caller might), it emits
`processor.MissingSignalIDSentinel` (`"MISSING_SIGNAL_ID"`) rather than an
empty string or a panic — loud and greppable in the vendor payload and the
audit log, instead of a silent unusable join key.

- **Bank-scoped mosaic (default, `KeyingBank`)** =
  `HMAC-SHA256(mosaicKeyMaterial(BANK_SALT, pepper), "v3|id|"+NormalizeID(national_id))`,
  where `mosaicKeyMaterial` folds the pepper in only when it's set (empty
  pepper is *not* an empty-key HMAC — `BANK_SALT` is always present). **Do
  not drop the `BANK_SALT` fold-in here** — that's the whole point of this
  keying mode: a mosaic that isn't reproducible without this institution's
  own secret.
- **Regional-scoped mosaic (opt-in, `KeyingRegional`)** =
  `HMAC-SHA256(pepper, "v3|id|"+NormalizeID(national_id))` — pepper ALONE,
  deliberately excluding `BANK_SALT`, preserved exactly as the old scheme
  worked. This is intentional cross-gateway derivability, gated behind
  explicit config — don't "fix" it to fold in the salt, and don't make it
  the default.
- **Fallback mosaic** (no national ID) folds `BANK_SALT` in via
  `mosaicKeyMaterial` **regardless of `MosaicKeying`** — it is always
  `ScopeBank`/`BasisInternalIDFallback`, since it's inherently tied to this
  institution's own internal ID + name and was never a cross-gateway-matching
  candidate.
- `"v3|id|"` / `"v3|local|"` prefixes are domain separation; `|` delimiters in
  every hashed concatenation prevent boundary collisions. Keep both when
  editing. `signal_id`'s `"v2|sigid|"` prefix and `FeatureVersion` are
  deliberately NOT coupled to `MosaicVersion` — don't bump them together
  reflexively.
- The destination-mosaic derivation mirrors the identity-mosaic derivation
  exactly (same keying, same formula per branch) — that equality is what
  makes mule-route following work, but ONLY when both sides used the same
  `MosaicKeying`. In bank mode that means route-following only works
  within one institution; regional mode is what preserves it across
  institutions. Changing one derivation without the other silently breaks
  route detection.

Any change to derivation needs a `MosaicVersion` bump and a flag-day note in
`docs/signal-schema-v2.md` — v2 and v3 (and any future version) must never
collide by construction; this codebase does not do dual emission.

### Wire contract lives in docs/signal-schema-v2.md

`docs/signal-schema-v2.md` documents the wire format (despite the stale
filename — it now documents mosaic v3). Changing the emitted payload,
headers, or the meaning of `mosaic_scope`/`mosaic_basis` means updating that
document in the same change. It used to be framed as a coordination doc for
the (now-gone) Hub team; it's now a plain reference for whoever consumes the
payload (vendor platform or an operator reading the standalone sink).

### Config (`internal/config`)

File (`CONFIG_PATH`, default `/config/gateway.json`) provides defaults; env vars
override. `Load()` caches into a package-level singleton — `Get()` returns the
same instance, and only `Reload()` clears it, so tests that manipulate env must
account for the cache.

`GatewayConfig.MosaicKeying` (env `MOSAIC_KEYING`, default `bank`) IS part of
the config struct, unlike the secrets below — it's a policy choice, not a
secret.

Note the asymmetry: `HMAC_SECRET` and the mosaic pepper (`MOSAIC_PEPPER`,
alias `REGIONAL_PEPPER` — see `pepperEnv` in `cmd/gateway/main.go`) are read
directly via `os.Getenv` at point of use (`main`, `outbound.go`,
`processTransaction`) and are **not** part of `GatewayConfig`. They are
secrets kept out of the config struct deliberately; don't "tidy" them into it.

### Coupled timeouts

`hubClient` uses a 2.5s per-attempt timeout and `ForwardToHubWithRetry` with
`maxRetries=2` costs ~8.25s worst case, sized to fit inside the server's 10s
`WriteTimeout`. Changing any one of those three numbers requires rechecking the
others.

### Error classification

`adapters.IsPermanent` distinguishes retryable from permanent failures (4xx
except 429, plus config errors). It is passed into `spool.New` as a function so
the spool package stays free of any dependency on `adapters` — keep that
direction of dependency. Permanent failures dead-letter to `<SPOOL_DIR>/dead/`
so one poisoned signal can't block the queue.

### Spool ordering and durability

`internal/spool` is a file-backed oldest-first queue. Filenames are
`<zero-padded unixnano>-<seq>.json`, and delivery order is a plain lexical sort
of those names — the zero-padding is load-bearing. Enqueue writes to `.tmp` then
renames, so a crash never leaves a half-signal. Only anonymized payloads are ever
written to disk; raw PII must never reach the spool.

By default `Enqueue` also fsyncs the temp file before rename and the spool
directory after it (`internal/dirsync.Sync`, same primitive PR #11 gave
`internal/auditlog` and `cmd/gateway/sink.go`), so the 202 a signal's enqueue
backs actually means the signal survives a host power loss, not just a
process crash — atomicity (the write-temp-then-rename) and durability
(fsync) are different guarantees; the rename alone only gave the former.
`SPOOL_FSYNC=false` opts out for operators who have measured their own
hardware — see README's "Durable spool" section for the measured cost and
exactly what that opt-out gives up. `Enqueue` releases `s.mu` before any of
this disk I/O (manual `Lock`/`Unlock` pairing, not `defer`, for exactly this
reason) — **the spool's bookkeeping mutex must never be held across a disk
operation**; preserve that if you touch `Enqueue` again.

## Conventions

- **Every commit needs a DCO sign-off** (`git commit -s`); unsigned commits can't
  be merged. See `CONTRIBUTING.md`.
- Never put real PII, production secrets, salts, peppers, or real bank
  identifiers in code, tests, or fixtures.
- Logs are structured `slog` JSON and must stay PII-free — existing handlers log
  only a 16-char mosaic prefix, never identifiers.
- Don't weaken a privacy or security guarantee (PII in logs or on the wire,
  unsalted hashes, dropped validation) without discussion in an issue first.
- Validation belongs in `RawData.Validate()` and checks values, not just key
  presence; the anonymizer assumes it has already run.
