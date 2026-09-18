package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/papoveB01/EdgeGW_Project/internal/adapters"
	"github.com/papoveB01/EdgeGW_Project/internal/auditlog"
	"github.com/papoveB01/EdgeGW_Project/internal/spool"
)

// signalAuditFields is the minimal subset of processor.AnonymizedSignal's
// JSON shape needed to write an audit record from raw payload bytes. It is
// defined here (rather than reusing the full struct) because both
// auditingForward and auditingSyncForward only ever have the already-
// marshaled payload bytes - never the struct itself - and the audit record
// intentionally carries far fewer fields than the wire payload (see
// auditlog.Record).
type signalAuditFields struct {
	SignalID       string `json:"signal_id"`
	MosaicVersion  int    `json:"mosaic_version"`
	FeatureVersion int    `json:"feature_version"`
	MosaicScope    string `json:"mosaic_scope"`
	// MosaicBasis is orthogonal to MosaicScope as of mosaic v3 (see
	// processor.BasisNationalID/BasisInternalIDFallback) - an audit record
	// that captured scope but silently dropped basis would still leave an
	// evidentiary gap, just a smaller one.
	MosaicBasis string `json:"mosaic_basis"`
}

// auditHealth tracks consecutive egress-audit-log write failures across
// whichever delivery path(s) are active (spool, synchronous, or both), so a
// single readiness signal (internal/adapters.AuditStatus, wired up via
// SetReadinessAuditStatus in main) reflects either one getting stuck.
//
// Safe for concurrent use: auditingForward is only ever called from the
// spool's single background forwarder goroutine, but auditingSyncForward
// can be called concurrently from many request-handling goroutines, and a
// single auditHealth is shared across both when both are active.
type auditHealth struct {
	mu       sync.Mutex
	failures int
}

func newAuditHealth() *auditHealth { return &auditHealth{} }

func (h *auditHealth) recordSuccess() {
	h.mu.Lock()
	h.failures = 0
	h.mu.Unlock()
}

// recordFailure increments the consecutive-failure count and returns the
// new value.
func (h *auditHealth) recordFailure() int {
	h.mu.Lock()
	h.failures++
	n := h.failures
	h.mu.Unlock()
	return n
}

// status reports the current consecutive-failure count as an
// adapters.AuditStatus snapshot, for internal/adapters.AuditStatusFunc.
func (h *auditHealth) status() adapters.AuditStatus {
	h.mu.Lock()
	defer h.mu.Unlock()
	return adapters.AuditStatus{ConsecutiveFailures: h.failures}
}

// hexDigest returns the hex-encoded SHA-256 digest of payload, used below
// to recognize retries of the same already-delivered payload. This is a
// local, cheap identity check on the closure's own state - it is
// independent of, and does not replace, auditlog.Record's own digest of
// the delivered bytes, which is the durable one that matters for the audit
// record itself.
func hexDigest(payload []byte) string {
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

// redeliveryGuard holds auditingForward's "this payload was already
// confirmed delivered; only the audit write is being retried" marker,
// split out into its own type (rather than a closure-local variable) so
// main.go can clear it from OUTSIDE auditingForward, via the spool's OnDead
// hook.
//
// That external clear is required, not optional. The guard's "same digest
// implies same still-queued item" reasoning depends on every item leaving
// the queue going through the wrapped ForwardFunc closure - but
// spool.forwardOldest has one path that does NOT: when os.ReadFile on the
// head item's file fails, it dead-letters the item directly and returns,
// never calling forward at all. If that fires on the exact item this guard
// is holding a digest for, the digest goes stale - it now describes an
// item that has LEFT the queue via a path this guard never observed. If
// the next queued item then happens to have a byte-identical marshaled
// payload (not far-fetched here: signal_id is a deterministic HMAC of
// transaction_ref, and the emitted timestamp is a 15-minute BUCKETED
// value, not time.Now(), so a genuine core-banking retry of the same
// transaction reproduces byte-identical JSON), the stale digest would
// match, the guard would report "already delivered", skip a delivery that
// never happened, and write an audit record asserting it did - a FALSE
// "this left the bank" record, which is worse than a missing one.
//
// spool.Run drives forwardOldest strictly one item at a time (never
// concurrent), so "some item was just dead-lettered" is an unambiguous
// signal that whatever this guard was holding no longer describes the
// current queue state - unconditionally clearing on every OnDead event is
// therefore always correct, never overly aggressive: it can, at worst,
// force one extra genuine delivery attempt for a different item that
// happens to arrive right after, which is the safe direction to err in.
type redeliveryGuard struct {
	mu     sync.Mutex
	digest string // "" = nothing pending
}

func newRedeliveryGuard() *redeliveryGuard { return &redeliveryGuard{} }

// matches reports whether digest is the one currently held as "already
// confirmed delivered, audit write still pending".
func (g *redeliveryGuard) matches(digest string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.digest != "" && g.digest == digest
}

// markDelivered records digest as confirmed delivered, audit write still
// pending.
func (g *redeliveryGuard) markDelivered(digest string) {
	g.mu.Lock()
	g.digest = digest
	g.mu.Unlock()
}

// clear discards whatever digest is held, if any. Called both when the
// audit write for the held digest finally succeeds (see auditingForward)
// and from the spool's OnDead hook (see main) so a dead-letter event that
// bypassed auditingForward entirely can't leave a stale marker behind.
func (g *redeliveryGuard) clear() {
	g.mu.Lock()
	g.digest = ""
	g.mu.Unlock()
}

// auditingForward wraps a spool.ForwardFunc so a durable audit record is
// written only after the destination has confirmed delivery of the exact
// payload bytes — never at enqueue or attempt time.
//
// Failure semantics (deliberate choice, see PR description): if delivery
// succeeds but the audit write then fails, this returns a non-nil,
// non-permanent error instead of masking it as success. Returned to
// internal/spool, that means the signal's file is NOT removed
// (spool.forwardOldest only calls os.Remove when forward returns nil) and
// the spool retries it. We prefer "retry, possibly duplicate" over
// "silently drop from the queue with no audit record": for a compliance
// control, a signal reaching the vendor twice is a nuisance; a signal that
// left the bank with no durable record of it is a silent regulatory gap.
//
// BOUNDING THE DUPLICATE STREAM: naively re-running deliver on every retry
// would re-POST the SAME signal to the destination roughly every 30s (the
// spool's backoff cap) for as long as the audit directory stays
// unwritable — an unbounded duplicate stream. For a vendor that computes
// velocity/count features, that doesn't just waste calls, it corrupts
// their inference. So guard remembers the digest of the payload most
// recently delivered successfully but NOT yet finished auditing: on the
// next retry of the SAME still-queued item (identical bytes, since
// spool.forwardOldest only advances past an item once this func returns
// nil), it skips deliver entirely and retries only the audit write. This
// is sound specifically because spool.Run drives forwardOldest from a
// single goroutine and never moves on to a different item while this one
// keeps failing (see spool.go's Run/forwardOldest) - so "the guarded
// digest matches" can only mean "this is the same item, being retried" -
// PROVIDED the guard is also cleared whenever an item leaves the queue by
// a path that bypasses this closure. See redeliveryGuard's doc comment for
// why that provision matters and how main wires it (the spool's OnDead
// hook) - without it, this optimization can produce a FALSE audit record.
//
// The one remaining duplicate window is a process restart while an item is
// stuck in this state: the in-memory guard doesn't survive it, so the
// signal is redelivered (at most) once more on the next attempt after
// restart. That is bounded — one extra duplicate per restart during an
// audit outage — not the unbounded per-backoff-interval stream this
// guards against.
//
// ESCALATION: every failure and success here is reported to health, so
// that after enough consecutive audit-write failures,
// internal/adapters.ReadinessCheckHandler (/readyz) flips unhealthy — a
// distinct, alertable signal instead of a counter (audit_write_failures on
// /metrics, also still recorded) operators have to know to watch.
func auditingForward(deliver spool.ForwardFunc, logger *auditlog.Logger, destination string, health *auditHealth, guard *redeliveryGuard) spool.ForwardFunc {
	return func(ctx context.Context, payload []byte) error {
		digest := hexDigest(payload)

		if !guard.matches(digest) {
			if err := deliver(ctx, payload); err != nil {
				return err
			}
			guard.markDelivered(digest)
		}

		if err := writeAuditFromPayload(logger, destination, payload, time.Now()); err != nil {
			adapters.RecordMetric("audit_write_failures", 1)
			n := health.recordFailure()
			return fmt.Errorf("signal delivered but audit record failed to write (consecutive audit failures: %d; NOT re-delivering to the destination while only the audit write is retried - see auditingForward doc comment): %w", n, err)
		}

		guard.clear()
		health.recordSuccess()
		return nil
	}
}

func writeAuditFromPayload(logger *auditlog.Logger, destination string, payload []byte, deliveredAt time.Time) error {
	var fields signalAuditFields
	if err := json.Unmarshal(payload, &fields); err != nil {
		return fmt.Errorf("failed to parse delivered signal for audit: %w", err)
	}
	return logger.Record(destination, fields.SignalID, fields.MosaicVersion, fields.FeatureVersion, fields.MosaicScope, fields.MosaicBasis, payload, deliveredAt)
}

// auditingSyncForward is auditingForward's counterpart for synchronous
// delivery (no spool: SPOOL_DIR unset). It applies the same
// after-confirmed-delivery-only rule and the same deliberate
// failure-semantics choice (prefer a duplicate over a missing record) as
// auditingForward - except here the "retry" that risks a duplicate is
// whatever the calling core banking system does in response to
// processTransaction returning 502 after delivery already succeeded, since
// there is no spool to retry on the gateway's behalf in this mode.
//
// It deliberately does NOT apply auditingForward's redelivery guard: each
// call here is an independent HTTP request/signal, not the spool retrying
// the same queued item, so there is nothing to deduplicate against.
//
// deliver operates on already-marshaled bytes (the same shape as
// spool.ForwardFunc) rather than a processor.AnonymizedSignal, and this
// wrapper hashes exactly those same bytes for the audit record - not a
// second, separately re-marshaled copy of them. An earlier version
// re-marshaled the signal struct a second time after delivery; that was
// byte-identical only because json.Marshal is deterministic and nothing
// mutated the signal in between - an unenforced invariant, given that
// AnonymizedSignal.Metadata is a map (a reference type shared across
// by-value struct copies) that a future deliver implementation touching it
// could silently break. Operating on bytes end-to-end instead makes "the
// recorded hash matches what was actually sent" structural, not
// incidental - see cmd/gateway's main, which now marshals the signal once
// and passes the resulting bytes through unchanged.
func auditingSyncForward(deliver func(ctx context.Context, payload []byte) error, logger *auditlog.Logger, destination string, health *auditHealth) func(ctx context.Context, payload []byte) error {
	return func(ctx context.Context, payload []byte) error {
		if err := deliver(ctx, payload); err != nil {
			return err
		}
		if err := writeAuditFromPayload(logger, destination, payload, time.Now()); err != nil {
			adapters.RecordMetric("audit_write_failures", 1)
			health.recordFailure()
			return fmt.Errorf("signal delivered but audit record failed to write (caller may retry, causing a duplicate delivery): %w", err)
		}
		health.recordSuccess()
		return nil
	}
}
