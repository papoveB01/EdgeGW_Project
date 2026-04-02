package processor

import (
	"math"
	"testing"
)

func TestHash(t *testing.T) {
	h := Hash("test")
	if len(h) != 64 {
		t.Fatalf("expected 64-char hex, got %d", len(h))
	}
	// Deterministic
	if Hash("test") != h {
		t.Fatal("hash not deterministic")
	}
	// Different inputs produce different hashes
	if Hash("test1") == Hash("test2") {
		t.Fatal("different inputs produced same hash")
	}
}

func TestMapToTier(t *testing.T) {
	tests := []struct {
		amount float64
		want   string
	}{
		{0, "TIER_1"}, {499.99, "TIER_1"}, {500, "TIER_1"},
		{501, "TIER_2"}, {2500, "TIER_2"},
		{2501, "TIER_3"}, {10000, "TIER_3"},
		{10001, "TIER_4"}, {999999, "TIER_4"},
	}
	for _, tt := range tests {
		got := MapToTier(tt.amount)
		if got != tt.want {
			t.Errorf("MapToTier(%v) = %s, want %s", tt.amount, got, tt.want)
		}
	}
}

func TestGeohash(t *testing.T) {
	// Known geohash for (57.64911, 10.40744) at precision 5 = "u4pru"
	gh := Geohash(57.64911, 10.40744, 5)
	if len(gh) != 5 {
		t.Fatalf("expected 5-char geohash, got %d: %s", len(gh), gh)
	}
	if gh != "u4pru" {
		t.Errorf("Geohash(57.64911, 10.40744, 5) = %s, want u4pru", gh)
	}

	// Nearby locations should share prefix
	gh1 := Geohash(57.649, 10.407, 5)
	gh2 := Geohash(57.650, 10.408, 5)
	if gh1[:3] != gh2[:3] {
		t.Errorf("nearby locations should share geohash prefix: %s vs %s", gh1, gh2)
	}

	// NaN returns unknown
	nan := math.NaN()
	if Geohash(nan, 10.0, 5) != "ZONE_UNKNOWN" {
		t.Error("NaN latitude should return ZONE_UNKNOWN")
	}
}

func TestBucketTimestamp(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"2026-01-15T14:07:33.123", "2026-01-15T14:00:00"},
		{"2026-01-15T14:14:59.999", "2026-01-15T14:00:00"},
		{"2026-01-15T14:15:00.000", "2026-01-15T14:15:00"},
		{"2026-01-15T14:29:33.123", "2026-01-15T14:15:00"},
		{"2026-01-15T14:44:33.123", "2026-01-15T14:30:00"},
		{"2026-01-15T14:59:33.123", "2026-01-15T14:45:00"},
	}
	for _, tt := range tests {
		got := BucketTimestamp(tt.input)
		if got != tt.want {
			t.Errorf("BucketTimestamp(%s) = %s, want %s", tt.input, got, tt.want)
		}
	}
}

func TestAnonymizeSignal_FieldDelimiters(t *testing.T) {
	// Two different identity inputs that would collide without delimiters
	raw1 := RawData{ID: "ab", Name: "cd", Account: "1234", Amount: 100, Timestamp: "2026-01-01T00:00:00"}
	raw2 := RawData{ID: "a", Name: "bcd", Account: "1234", Amount: 100, Timestamp: "2026-01-01T00:00:00"}

	sig1 := AnonymizeSignal(raw1, "BNK", "salt", "pepper", 10000)
	sig2 := AnonymizeSignal(raw2, "BNK", "salt", "pepper", 10000)

	if sig1.IdentityMosaic == sig2.IdentityMosaic {
		t.Error("field delimiter collision: different inputs produced same mosaic")
	}
}

func TestAnonymizeSignal_NearThreshold(t *testing.T) {
	raw := RawData{ID: "1", Name: "Test", Account: "ACC", Amount: 9600, Timestamp: "2026-01-01T00:00:00"}
	sig := AnonymizeSignal(raw, "BNK", "salt", "pepper", 10000)

	if _, ok := sig.Metadata["is_near_threshold"]; !ok {
		t.Error("expected is_near_threshold flag for 9600 with threshold 10000")
	}

	raw.Amount = 9000
	sig = AnonymizeSignal(raw, "BNK", "salt", "pepper", 10000)
	if _, ok := sig.Metadata["is_near_threshold"]; ok {
		t.Error("should not flag 9000 as near threshold")
	}
}

func TestAnonymizeSignal_DestinationMosaic(t *testing.T) {
	raw := RawData{ID: "1", Name: "Test", Account: "ACC", Amount: 100, Timestamp: "2026-01-01T00:00:00", CounterpartyID: "CP123"}
	sig := AnonymizeSignal(raw, "BNK", "salt", "pepper", 10000)

	if sig.DestinationMosaic == "" {
		t.Error("expected destination_mosaic when counterparty_id is set")
	}
}

func TestAnonymizeSignal_DeviceAndIPHash(t *testing.T) {
	raw := RawData{ID: "1", Name: "Test", Account: "ACC", Amount: 100, Timestamp: "2026-01-01T00:00:00",
		DeviceID: "device123", IP: "192.168.1.1"}
	sig := AnonymizeSignal(raw, "BNK", "salt", "pepper", 10000)

	if _, ok := sig.Metadata["device_id_hash"]; !ok {
		t.Error("expected device_id_hash")
	}
	if _, ok := sig.Metadata["ip_hash"]; !ok {
		t.Error("expected ip_hash")
	}

	// Pre-hashed should pass through
	raw2 := RawData{ID: "1", Name: "Test", Account: "ACC", Amount: 100, Timestamp: "2026-01-01T00:00:00",
		DeviceIDHash: "prehashed_device", IPHash: "prehashed_ip"}
	sig2 := AnonymizeSignal(raw2, "BNK", "salt", "pepper", 10000)

	if sig2.Metadata["device_id_hash"] != "prehashed_device" {
		t.Error("pre-hashed device_id_hash should pass through")
	}
	if sig2.Metadata["ip_hash"] != "prehashed_ip" {
		t.Error("pre-hashed ip_hash should pass through")
	}
}
