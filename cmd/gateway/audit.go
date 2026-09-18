package main

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/papoveB01/EdgeGW_Project/internal/adapters"
	"github.com/papoveB01/EdgeGW_Project/internal/auditlog"
	"github.com/papoveB01/EdgeGW_Project/internal/processor"
	"github.com/papoveB01/EdgeGW_Project/internal/spool"
)

// signalAuditFields is the minimal subset of processor.AnonymizedSignal's
// JSON shape needed to write an audit record from raw payload bytes. It is
// defined here (rather than reusing the full struct) because auditingForward
// only ever has the already-marshaled payload the spool queued or read back
// from disk — never the struct itself — and the audit record intentionally
// carries far fewer fields than the wire payload (see auditlog.Record).
type signalAuditFields struct {
	SignalID       string `json:"signal_id"`
	MosaicVersion  int    `json:"mosaic_version"`
	FeatureVersion int    `json:"feature_version"`
	MosaicScope    string `json:"mosaic_scope"`
}

// auditingForward wraps a spool.ForwardFunc so a durable audit record is
// written only after the destination has confirmed delivery of the exact
// payload bytes — never at enqueue or attempt time.
//
// Failure semantics (deliberate choice, see PR description): if delivery
// succeeds but the audit write then fails, this returns a non-nil,
// non-permanent error instead of nil. Returned to internal/spool, that
// means the signal's file is NOT removed (spool.forwardOldest only calls
// os.Remove when forward returns nil) and the spool retries it — which
// re-runs the underlying delivery too, so a transient audit-write failure
// costs a DUPLICATE delivery to the destination, not a missing audit
// record. We prefer that direction of failure deliberately: for a
// compliance control, "the vendor got this signal twice" is a nuisance;
// "the bank has no durable record this signal ever left" is a silent
// regulatory gap. adapters.RecordMetric("audit_write_failures", ...) makes
// this path observable so operators aren't relying on log-diving to notice
// it's happening.
//
// One consequence worth naming: if the audit directory becomes persistently
// unwritable (not transient — e.g. permissions, disk full), this will keep
// re-delivering the same signal to the destination on every spool retry
// (bounded by the spool's exponential backoff, capped at 30s) until the
// audit path is fixed or the operator intervenes. That is the cost of
// choosing duplicate-over-missing, and it is why audit_write_failures
// should be alerted on rather than only logged.
func auditingForward(deliver spool.ForwardFunc, logger *auditlog.Logger, destination string) spool.ForwardFunc {
	return func(ctx context.Context, payload []byte) error {
		if err := deliver(ctx, payload); err != nil {
			return err
		}
		if err := writeAuditFromPayload(logger, destination, payload, time.Now()); err != nil {
			adapters.RecordMetric("audit_write_failures", 1)
			return fmt.Errorf("signal delivered but audit record failed to write (will retry, may duplicate delivery to destination): %w", err)
		}
		return nil
	}
}

func writeAuditFromPayload(logger *auditlog.Logger, destination string, payload []byte, deliveredAt time.Time) error {
	var fields signalAuditFields
	if err := json.Unmarshal(payload, &fields); err != nil {
		return fmt.Errorf("failed to parse delivered signal for audit: %w", err)
	}
	return logger.Record(destination, fields.SignalID, fields.MosaicVersion, fields.FeatureVersion, fields.MosaicScope, payload, deliveredAt)
}

// auditingSyncForward is auditingForward's counterpart for synchronous
// delivery (no spool: SPOOL_DIR unset). It applies the identical
// after-confirmed-delivery-only rule and the identical deliberate
// failure-semantics choice (prefer a duplicate over a missing record) —
// except here the "retry" that risks a duplicate is whatever the calling
// core banking system does in response to processTransaction returning 502
// after syncForward already delivered successfully, since there is no spool
// to retry on the gateway's behalf in this mode.
//
// The audited payload is re-marshaled from signal rather than intercepted
// from the underlying transport call, because ForwardToHub/localSink.Forward
// marshal internally and don't expose the exact bytes they sent. json.Marshal
// is deterministic for a given struct value (map keys included — Go's
// encoding/json sorts them), and signal is not mutated between the transport
// call and this re-marshal, so the digest is still a digest of the exact
// bytes delivered.
func auditingSyncForward(deliver func(ctx context.Context, signal processor.AnonymizedSignal) error, logger *auditlog.Logger, destination string) func(ctx context.Context, signal processor.AnonymizedSignal) error {
	return func(ctx context.Context, signal processor.AnonymizedSignal) error {
		if err := deliver(ctx, signal); err != nil {
			return err
		}
		payload, err := json.Marshal(signal)
		if err != nil {
			adapters.RecordMetric("audit_write_failures", 1)
			return fmt.Errorf("signal delivered but failed to encode it for the audit record: %w", err)
		}
		if err := logger.Record(destination, signal.SignalID, signal.MosaicVersion, signal.FeatureVersion, signal.MosaicScope, payload, time.Now()); err != nil {
			adapters.RecordMetric("audit_write_failures", 1)
			return fmt.Errorf("signal delivered but audit record failed to write (caller may retry, causing a duplicate delivery): %w", err)
		}
		return nil
	}
}
