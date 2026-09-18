package spool

import (
	"context"
	"testing"
)

// BenchmarkEnqueue measures Enqueue's per-op latency and implied throughput
// ceiling with and without fsync, so the tradeoff behind SPOOL_FSYNC's
// default (on) is backed by a measurement taken on this machine rather than
// asserted. See the PR description for issue #13 for the numbers this
// produced and how they compare to this repo's ~23 tx/sec average /
// several-times-that-peak estimate for a mid-size retail bank.
//
// Run with: go test -bench BenchmarkEnqueue -benchtime=2s -run '^$' ./internal/spool/
func BenchmarkEnqueue(b *testing.B) {
	payload := []byte(`{"signal_id":"bench-sig","identity_mosaic":"0123456789abcdef0123456789abcdef","mosaic_scope":"bank","mosaic_basis":"national_id","amount_tier":"tier_2","metadata":{"key":"value"}}`)

	for _, fsync := range []bool{true, false} {
		name := "FsyncOn"
		if !fsync {
			name = "FsyncOff"
		}
		b.Run(name, func(b *testing.B) {
			dir := b.TempDir()
			s, err := New(dir, b.N+1, func(ctx context.Context, payload []byte) error {
				return nil
			}, isPerm, Hooks{})
			if err != nil {
				b.Fatal(err)
			}
			s.fsyncEnabled = fsync
			// Never run the background forwarder: this benchmark measures
			// Enqueue in isolation, not delivery. maxDepth above is sized
			// to b.N+1 so every iteration's Enqueue succeeds without
			// ErrFull regardless of b.N.

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if err := s.Enqueue(payload); err != nil {
					b.Fatalf("Enqueue: %v", err)
				}
			}
			b.StopTimer()

			opsPerSec := float64(b.N) / b.Elapsed().Seconds()
			b.ReportMetric(opsPerSec, "ops/sec")
		})
	}
}

// BenchmarkEnqueueParallel is BenchmarkEnqueue's concurrent counterpart:
// /process handles concurrent inbound requests from core banking, so this
// measures Enqueue's throughput ceiling under concurrent callers rather
// than a single serial caller, which is what actually bounds the gateway's
// sustainable transactions/sec.
func BenchmarkEnqueueParallel(b *testing.B) {
	payload := []byte(`{"signal_id":"bench-sig","identity_mosaic":"0123456789abcdef0123456789abcdef","mosaic_scope":"bank","mosaic_basis":"national_id","amount_tier":"tier_2","metadata":{"key":"value"}}`)

	for _, fsync := range []bool{true, false} {
		name := "FsyncOn"
		if !fsync {
			name = "FsyncOff"
		}
		b.Run(name, func(b *testing.B) {
			dir := b.TempDir()
			s, err := New(dir, b.N+1, func(ctx context.Context, payload []byte) error {
				return nil
			}, isPerm, Hooks{})
			if err != nil {
				b.Fatal(err)
			}
			s.fsyncEnabled = fsync

			b.ReportAllocs()
			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					if err := s.Enqueue(payload); err != nil {
						b.Fatalf("Enqueue: %v", err)
					}
				}
			})
			b.StopTimer()

			opsPerSec := float64(b.N) / b.Elapsed().Seconds()
			b.ReportMetric(opsPerSec, "ops/sec")
		})
	}
}
