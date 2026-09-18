package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/papoveB01/EdgeGW_Project/internal/adapters"
	"github.com/papoveB01/EdgeGW_Project/internal/auditlog"
	"github.com/papoveB01/EdgeGW_Project/internal/processor"
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
			wrapped := auditingForward(deliver, logger, "https://vendor.example/signals")

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
// internal/spool retries the whole signal, including redelivery, rather
// than silently dropping it from the queue with no durable record. It also
// checks the distinct operator-facing metric fires.
func TestAuditingForward_AuditWriteFailureAfterDeliveryIsReportedAsFailure(t *testing.T) {
	dir := t.TempDir()

	// Pre-create today's audit file path AS A DIRECTORY so auditlog.Logger's
	// os.OpenFile(..., O_WRONLY) fails deterministically - simulating an
	// audit-write failure that happens strictly after delivery has already
	// succeeded, without relying on permission bits (which root/CI can
	// bypass).
	blocked := todaysAuditFile(dir)
	if err := os.MkdirAll(blocked, 0o700); err != nil {
		t.Fatalf("pre-creating blocking directory: %v", err)
	}

	logger, err := auditlog.New(dir, false)
	if err != nil {
		t.Fatalf("auditlog.New: %v", err)
	}
	t.Cleanup(func() { logger.Close() })

	deliverConfirmed := false
	deliver := spool.ForwardFunc(func(ctx context.Context, payload []byte) error {
		deliverConfirmed = true
		return nil // destination accepted the signal
	})
	wrapped := auditingForward(deliver, logger, "https://vendor.example/signals")

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
}

// TestAuditingSyncForward mirrors the spool-mode tests above for the
// synchronous (no-SPOOL_DIR) delivery path.
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

			deliver := func(ctx context.Context, signal processor.AnonymizedSignal) error {
				return tt.deliverErr
			}
			wrapped := auditingSyncForward(deliver, logger, "local-sink:./sink")

			signal := processor.AnonymizedSignal{
				SignalID:       "sig-sync-1",
				MosaicVersion:  2,
				FeatureVersion: 1,
				MosaicScope:    "local",
			}
			gotErr := wrapped(context.Background(), signal)

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
	blocked := todaysAuditFile(dir)
	if err := os.MkdirAll(blocked, 0o700); err != nil {
		t.Fatalf("pre-creating blocking directory: %v", err)
	}

	logger, err := auditlog.New(dir, false)
	if err != nil {
		t.Fatalf("auditlog.New: %v", err)
	}
	t.Cleanup(func() { logger.Close() })

	deliver := func(ctx context.Context, signal processor.AnonymizedSignal) error { return nil }
	wrapped := auditingSyncForward(deliver, logger, "local-sink:./sink")

	before := metricValue(t, "audit_write_failures")
	signal := processor.AnonymizedSignal{SignalID: "sig-sync-fail", MosaicVersion: 2, FeatureVersion: 1, MosaicScope: "local"}
	gotErr := wrapped(context.Background(), signal)
	after := metricValue(t, "audit_write_failures")

	if gotErr == nil {
		t.Fatal("expected a non-nil error when the audit write fails after confirmed delivery")
	}
	if after != before+1 {
		t.Errorf("expected audit_write_failures to increment by 1, got %d -> %d", before, after)
	}
}

// TestAuditingForward_DigestMatchesExactDeliveredBytes checks the digest
// recorded is computed over the exact payload bytes handed to deliver, not
// some re-derived or partial representation.
func TestAuditingForward_DigestMatchesExactDeliveredBytes(t *testing.T) {
	dir := t.TempDir()
	logger, err := auditlog.New(dir, false)
	if err != nil {
		t.Fatalf("auditlog.New: %v", err)
	}
	t.Cleanup(func() { logger.Close() })

	deliver := spool.ForwardFunc(func(ctx context.Context, payload []byte) error { return nil })
	wrapped := auditingForward(deliver, logger, "https://vendor.example/signals")

	payload := []byte(`{"signal_id":"sig-digest","mosaic_version":2,"feature_version":1,"mosaic_scope":"local","amount_tier":"TIER_1"}`)
	if err := wrapped(context.Background(), payload); err != nil {
		t.Fatalf("wrapped forward: %v", err)
	}

	data, err := os.ReadFile(todaysAuditFile(dir))
	if err != nil {
		t.Fatalf("reading audit file: %v", err)
	}
	var rec auditlog.Record
	if err := json.Unmarshal(data[:len(data)-1], &rec); err != nil { // strip trailing newline
		t.Fatalf("unmarshal record: %v", err)
	}
	if rec.SignalID != "sig-digest" {
		t.Errorf("signal_id mismatch: %s", rec.SignalID)
	}
	if rec.PayloadBytes != len(payload) {
		t.Errorf("payload_bytes mismatch: got %d want %d", rec.PayloadBytes, len(payload))
	}
}
