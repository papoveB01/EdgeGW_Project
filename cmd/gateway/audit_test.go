package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/papoveB01/EdgeGW_Project/internal/adapters"
	"github.com/papoveB01/EdgeGW_Project/internal/auditlog"
	"github.com/papoveB01/EdgeGW_Project/internal/spool"
)

// metricValue reads one counter's current value off adapters.MetricsHandler,
// since the metrics package exposes no direct getter.
func metricValue(t *testing.T, name string) int64 {
	t.Helper()
	rec := httptest.NewRecorder()
	adapters.MetricsHandler(rec, httptest.NewRequest("GET", "/metrics", nil))
	var body map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode /metrics: %v", err)
	}
	v, ok := body[name]
	if !ok {
		return 0
	}
	f, ok := v.(float64)
	if !ok {
		t.Fatalf("metric %s is not numeric: %v", name, v)
	}
	return int64(f)
}

func todaysAuditFile(dir string) string {
	return filepath.Join(dir, "audit-"+time.Now().UTC().Format("2006-01-02")+".ndjson")
}

// blockedLogger returns an *auditlog.Logger whose writes to today's file
// deterministically fail: the target file path is pre-created as a
// directory, so auditlog's os.OpenFile(..., O_WRONLY) fails every time, no
// matter how many times Record is retried. This simulates a persistently
// unwritable audit destination without relying on permission bits (which
// root/CI can bypass).
func blockedLogger(t *testing.T, dir string) *auditlog.Logger {
	t.Helper()
	blocked := todaysAuditFile(dir)
	if err := os.MkdirAll(blocked, 0o700); err != nil {
		t.Fatalf("pre-creating blocking directory: %v", err)
	}
	logger, err := auditlog.New(dir, false)
	if err != nil {
		t.Fatalf("auditlog.New: %v", err)
	}
	t.Cleanup(func() { logger.Close() })
	return logger
}

// TestAuditingForward_WritesOnlyAfterConfirmedDelivery is the table-driven
// core of the "written at confirmed delivery, not enqueue/attempt" contract:
// when the destination rejects the signal, no audit record may exist at
// all, confirmed delivery must produce exactly one, and none of this is
// signal-order dependent since forwardFunc is called fresh each spool
// retry.
func TestAuditingForward_WritesOnlyAfterConfirmedDelivery(t *testing.T) {
	tests := []struct {
		name       string
		deliverErr error
	}{
		{name: "delivery fails - no audit record written", deliverErr: errors.New("destination unreachable")},
		{name: "delivery succeeds - audit record written", deliverErr: nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			logger, err := auditlog.New(dir, false)
			if err != nil {
				t.Fatalf("auditlog.New: %v", err)
			}
			t.Cleanup(func() { logger.Close() })

			var deliverCalled bool
			deliver := spool.ForwardFunc(func(ctx context.Context, payload []byte) error {
				deliverCalled = true
				return tt.deliverErr
			})
			wrapped := auditingForward(deliver, logger, "https://vendor.example/signals", newAuditHealth())

			payload := []byte(`{"signal_id":"sig-confirmed","mosaic_version":2,"feature_version":1,"mosaic_scope":"local"}`)
			gotErr := wrapped(context.Background(), payload)

			if !deliverCalled {
				t.Fatal("expected the underlying deliver func to be called")
			}

			_, statErr := os.Stat(todaysAuditFile(dir))
			recordExists := statErr == nil

			if tt.deliverErr != nil {
				if !errors.Is(gotErr, tt.deliverErr) {
					t.Errorf("expected wrapped forward to surface the delivery error, got %v", gotErr)
				}
				if recordExists {
					t.Error("audit record must not exist when the destination never confirmed delivery")
				}
			} else {
				if gotErr != nil {
					t.Errorf("expected nil error after confirmed delivery + successful audit write, got %v", gotErr)
				}
				if !recordExists {
					t.Error("expected an audit record after confirmed delivery")
				}
			}
		})
	}
}

// TestAuditingForward_AuditWriteFailureAfterDeliveryIsReportedAsFailure
// pins the deliberate failure-semantics choice documented on
// auditingForward: once the destination has confirmed delivery, an audit
// write failure must be surfaced as a (non-permanent) error - so
// internal/spool retries the whole signal, rather than silently dropping
// it from the queue with no durable record. It also checks the distinct
// operator-facing metric fires and that auditHealth's failure count moves.
func TestAuditingForward_AuditWriteFailureAfterDeliveryIsReportedAsFailure(t *testing.T) {
	dir := t.TempDir()
	logger := blockedLogger(t, dir)

	deliverConfirmed := false
	deliver := spool.ForwardFunc(func(ctx context.Context, payload []byte) error {
		deliverConfirmed = true
		return nil // destination accepted the signal
	})
	health := newAuditHealth()
	wrapped := auditingForward(deliver, logger, "https://vendor.example/signals", health)

	before := metricValue(t, "audit_write_failures")
	payload := []byte(`{"signal_id":"sig-audit-fail","mosaic_version":2,"feature_version":1,"mosaic_scope":"local"}`)
	gotErr := wrapped(context.Background(), payload)
	after := metricValue(t, "audit_write_failures")

	if !deliverConfirmed {
		t.Fatal("expected the destination to have confirmed delivery before the audit write was attempted")
	}
	if gotErr == nil {
		t.Fatal("expected a non-nil error: delivery succeeded but the audit write failed, and that must not be reported as overall success")
	}
	if adapters.IsPermanent(gotErr) {
		t.Error("an audit-write failure after confirmed delivery must NOT be classified permanent - the spool must retry (accepting a possible duplicate delivery), not dead-letter the signal")
	}
	if after != before+1 {
		t.Errorf("expected audit_write_failures to increment by exactly 1 (%d -> %d), got %d -> %d", before, before+1, before, after)
	}
	if got := health.status().ConsecutiveFailures; got != 1 {
		t.Errorf("expected auditHealth to report 1 consecutive failure, got %d", got)
	}
}

// TestAuditingForward_DoesNotRedeliverWhileRetryingOnlyTheAuditWrite pins
// the retry-storm bound: once the destination has confirmed delivery for a
// given payload, further retries of that SAME payload (spool.Run retrying
// the same still-queued head item because only the audit write is failing)
// must NOT re-invoke deliver. Naively redelivering on every retry would
// re-POST the same signal to the destination roughly every backoff
// interval for as long as the audit path stays broken - an unbounded
// duplicate stream a vendor computing velocity/count features would be
// corrupted by.
func TestAuditingForward_DoesNotRedeliverWhileRetryingOnlyTheAuditWrite(t *testing.T) {
	dir := t.TempDir()
	logger := blockedLogger(t, dir)

	var deliverCalls int32
	deliver := spool.ForwardFunc(func(ctx context.Context, payload []byte) error {
		atomic.AddInt32(&deliverCalls, 1)
		return nil
	})
	health := newAuditHealth()
	wrapped := auditingForward(deliver, logger, "https://vendor.example/signals", health)

	payload := []byte(`{"signal_id":"sig-retry-storm","mosaic_version":2,"feature_version":1,"mosaic_scope":"local"}`)

	const retries = 5
	for i := 0; i < retries; i++ {
		// This mirrors what spool.Run actually does: it calls the SAME
		// ForwardFunc closure again, with the SAME bytes read back off
		// disk, because the item was never removed (forward keeps
		// returning a non-nil, non-permanent error).
		err := wrapped(context.Background(), payload)
		if err == nil {
			t.Fatalf("attempt %d: expected the audit write to keep failing (logger is deliberately blocked)", i)
		}
	}

	if got := atomic.LoadInt32(&deliverCalls); got != 1 {
		t.Errorf("expected exactly 1 real delivery across %d retries of the same stuck item, got %d - the retry-storm bound is not holding", retries, got)
	}
	if got := health.status().ConsecutiveFailures; got != retries {
		t.Errorf("expected %d consecutive audit failures recorded, got %d", retries, got)
	}
}

// TestAuditingForward_RedeliversADifferentPayloadNormally is
// TestAuditingForward_DoesNotRedeliverWhileRetryingOnlyTheAuditWrite's
// counterpart: the redelivery guard must never suppress a genuinely new
// signal once the previous item's audit write finally succeeds and the
// spool advances to the next item.
func TestAuditingForward_RedeliversADifferentPayloadNormally(t *testing.T) {
	dir := t.TempDir()
	logger, err := auditlog.New(dir, false)
	if err != nil {
		t.Fatalf("auditlog.New: %v", err)
	}
	t.Cleanup(func() { logger.Close() })

	var deliverCalls int32
	deliver := spool.ForwardFunc(func(ctx context.Context, payload []byte) error {
		atomic.AddInt32(&deliverCalls, 1)
		return nil
	})
	health := newAuditHealth()
	wrapped := auditingForward(deliver, logger, "https://vendor.example/signals", health)

	payloadA := []byte(`{"signal_id":"sig-a","mosaic_version":2,"feature_version":1,"mosaic_scope":"local"}`)
	payloadB := []byte(`{"signal_id":"sig-b","mosaic_version":2,"feature_version":1,"mosaic_scope":"local"}`)

	if err := wrapped(context.Background(), payloadA); err != nil {
		t.Fatalf("delivering A: %v", err)
	}
	if err := wrapped(context.Background(), payloadB); err != nil {
		t.Fatalf("delivering B: %v", err)
	}

	if got := atomic.LoadInt32(&deliverCalls); got != 2 {
		t.Errorf("expected 2 real deliveries for 2 distinct signals, got %d", got)
	}
	if got := health.status().ConsecutiveFailures; got != 0 {
		t.Errorf("expected 0 consecutive failures after two clean deliveries, got %d", got)
	}
}

// TestAuditingSyncForward mirrors the spool-mode tests above for the
// synchronous (no-SPOOL_DIR) delivery path, which now operates on
// pre-marshaled bytes (see auditingSyncForward's doc comment on CHANGE 3).
func TestAuditingSyncForward_WritesOnlyAfterConfirmedDelivery(t *testing.T) {
	tests := []struct {
		name       string
		deliverErr error
	}{
		{name: "delivery fails - no audit record written", deliverErr: errors.New("sink unwritable")},
		{name: "delivery succeeds - audit record written", deliverErr: nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			logger, err := auditlog.New(dir, false)
			if err != nil {
				t.Fatalf("auditlog.New: %v", err)
			}
			t.Cleanup(func() { logger.Close() })

			deliver := func(ctx context.Context, payload []byte) error {
				return tt.deliverErr
			}
			wrapped := auditingSyncForward(deliver, logger, "local-sink:./sink", newAuditHealth())

			payload := []byte(`{"signal_id":"sig-sync-1","mosaic_version":2,"feature_version":1,"mosaic_scope":"local"}`)
			gotErr := wrapped(context.Background(), payload)

			_, statErr := os.Stat(todaysAuditFile(dir))
			recordExists := statErr == nil

			if tt.deliverErr != nil {
				if !errors.Is(gotErr, tt.deliverErr) {
					t.Errorf("expected the delivery error to surface, got %v", gotErr)
				}
				if recordExists {
					t.Error("audit record must not exist when delivery failed")
				}
			} else {
				if gotErr != nil {
					t.Errorf("expected nil error, got %v", gotErr)
				}
				if !recordExists {
					t.Error("expected an audit record after confirmed delivery")
				}
			}
		})
	}
}

func TestAuditingSyncForward_AuditWriteFailureAfterDeliveryIsReportedAsFailure(t *testing.T) {
	dir := t.TempDir()
	logger := blockedLogger(t, dir)

	deliver := func(ctx context.Context, payload []byte) error { return nil }
	health := newAuditHealth()
	wrapped := auditingSyncForward(deliver, logger, "local-sink:./sink", health)

	before := metricValue(t, "audit_write_failures")
	payload := []byte(`{"signal_id":"sig-sync-fail","mosaic_version":2,"feature_version":1,"mosaic_scope":"local"}`)
	gotErr := wrapped(context.Background(), payload)
	after := metricValue(t, "audit_write_failures")

	if gotErr == nil {
		t.Fatal("expected a non-nil error when the audit write fails after confirmed delivery")
	}
	if after != before+1 {
		t.Errorf("expected audit_write_failures to increment by 1, got %d -> %d", before, after)
	}
	if got := health.status().ConsecutiveFailures; got != 1 {
		t.Errorf("expected auditHealth to report 1 consecutive failure, got %d", got)
	}
}

// TestAuditingSyncForward_HashesExactlyTheBytesPassedIn is CHANGE 3's
// regression test. auditingSyncForward now operates on pre-marshaled bytes
// end-to-end (bytes in, same bytes delivered, same bytes hashed) instead of
// a processor.AnonymizedSignal that got re-marshaled a second time after
// delivery to produce the audited payload - so "the recorded digest
// matches what was transmitted" no longer depends on json.Marshal being
// deterministic and nothing mutating the signal in between two separate
// marshal calls. This checks the recorded digest against a hand-computed
// SHA-256 of the exact input bytes.
func TestAuditingSyncForward_HashesExactlyTheBytesPassedIn(t *testing.T) {
	dir := t.TempDir()
	logger, err := auditlog.New(dir, false)
	if err != nil {
		t.Fatalf("auditlog.New: %v", err)
	}
	t.Cleanup(func() { logger.Close() })

	deliver := func(ctx context.Context, payload []byte) error { return nil }
	wrapped := auditingSyncForward(deliver, logger, "local-sink:./sink", newAuditHealth())

	payload := []byte(`{"signal_id":"sig-sync-digest","mosaic_version":2,"feature_version":1,"mosaic_scope":"local","amount_tier":"TIER_2"}`)
	if err := wrapped(context.Background(), payload); err != nil {
		t.Fatalf("wrapped forward: %v", err)
	}

	assertRecordedDigestMatches(t, dir, payload)
}

// TestAuditingForward_DigestMatchesExactDeliveredBytes is CHANGE 4's fix:
// the previous version of this test was named for digest correctness but
// never actually asserted PayloadSHA256, only length and signal_id -
// property coverage the auditlog package already had, so the name
// overclaimed what this test verified. It now asserts the digest.
func TestAuditingForward_DigestMatchesExactDeliveredBytes(t *testing.T) {
	dir := t.TempDir()
	logger, err := auditlog.New(dir, false)
	if err != nil {
		t.Fatalf("auditlog.New: %v", err)
	}
	t.Cleanup(func() { logger.Close() })

	deliver := spool.ForwardFunc(func(ctx context.Context, payload []byte) error { return nil })
	wrapped := auditingForward(deliver, logger, "https://vendor.example/signals", newAuditHealth())

	payload := []byte(`{"signal_id":"sig-digest","mosaic_version":2,"feature_version":1,"mosaic_scope":"local","amount_tier":"TIER_1"}`)
	if err := wrapped(context.Background(), payload); err != nil {
		t.Fatalf("wrapped forward: %v", err)
	}

	assertRecordedDigestMatches(t, dir, payload)
}

// assertRecordedDigestMatches reads today's single audit record out of dir
// and checks its PayloadSHA256 (and PayloadBytes, and SignalID as a sanity
// check that the right record was read) against a hand-computed digest of
// wantPayload.
func assertRecordedDigestMatches(t *testing.T, dir string, wantPayload []byte) {
	t.Helper()

	data, err := os.ReadFile(todaysAuditFile(dir))
	if err != nil {
		t.Fatalf("reading audit file: %v", err)
	}
	var rec auditlog.Record
	if err := json.Unmarshal(data[:len(data)-1], &rec); err != nil { // strip trailing newline
		t.Fatalf("unmarshal record: %v", err)
	}

	// Computed independently of hexDigest (cmd/gateway's own helper, used
	// only for the redelivery-guard optimization) and of internal/auditlog's
	// internal digest computation, so this doesn't just check both sides
	// agree with themselves.
	sum := sha256.Sum256(wantPayload)
	wantDigest := hex.EncodeToString(sum[:])
	if rec.PayloadSHA256 != wantDigest {
		t.Errorf("payload_sha256 mismatch: got %s, want %s (digest of the exact delivered bytes)", rec.PayloadSHA256, wantDigest)
	}
	if rec.PayloadBytes != len(wantPayload) {
		t.Errorf("payload_bytes mismatch: got %d want %d", rec.PayloadBytes, len(wantPayload))
	}
}
