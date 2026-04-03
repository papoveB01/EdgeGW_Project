package processor

import (
	"math"
	"strings"
	"testing"
)

func TestHash(t *testing.T) {
	// SHA-256 of empty string is well-known
	emptyHash := Hash("")
	if emptyHash != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Errorf("Hash of empty string = %s, want e3b0c44...", emptyHash)
	}

	// Deterministic
	h1 := Hash("test-input")
	h2 := Hash("test-input")
	if h1 != h2 {
		t.Error("Hash is not deterministic")
	}

	// Different inputs produce different outputs
	h3 := Hash("different-input")
	if h1 == h3 {
		t.Error("Different inputs produced the same hash")
	}

	// Output is 64-char hex string
	if len(h1) != 64 {
		t.Errorf("Hash length = %d, want 64", len(h1))
	}
}

func TestTruncateMosaic(t *testing.T) {
	tests := []struct {
		name string
		s    string
		n    int
		want string
	}{
		{"long string", "abcdefghijklmnopqrstuvwxyz", 16, "abcdefghijklmnop"},
		{"exact length", "abcdefghijklmnop", 16, "abcdefghijklmnop"},
		{"short string", "abc", 16, "abc"},
		{"empty string", "", 16, ""},
		{"zero n", "abc", 0, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := TruncateMosaic(tt.s, tt.n)
			if got != tt.want {
				t.Errorf("TruncateMosaic(%q, %d) = %q, want %q", tt.s, tt.n, got, tt.want)
			}
		})
	}
}

func TestMapToTier(t *testing.T) {
	tests := []struct {
		amount float64
		want   string
	}{
		{0, "TIER_1"},
		{500, "TIER_1"},
		{500.01, "TIER_2"},
		{2500, "TIER_2"},
		{2500.01, "TIER_3"},
		{10000, "TIER_3"},
		{10000.01, "TIER_4"},
		{999999, "TIER_4"},
	}
	for _, tt := range tests {
		got := MapToTier(tt.amount)
		if got != tt.want {
			t.Errorf("MapToTier(%v) = %s, want %s", tt.amount, got, tt.want)
		}
	}
}

func TestGetGeohash(t *testing.T) {
	// NaN returns unknown
	if got := GetGeohash(math.NaN(), 3.0, 5); got != "unknown" {
		t.Errorf("GetGeohash(NaN, 3.0, 5) = %s, want unknown", got)
	}
	if got := GetGeohash(6.0, math.NaN(), 5); got != "unknown" {
		t.Errorf("GetGeohash(6.0, NaN, 5) = %s, want unknown", got)
	}

	// Precision is respected
	h3 := GetGeohash(6.5244, 3.3792, 3)
	h5 := GetGeohash(6.5244, 3.3792, 5)
	h7 := GetGeohash(6.5244, 3.3792, 7)
	if len(h3) != 3 {
		t.Errorf("GetGeohash precision=3 returned length %d", len(h3))
	}
	if len(h5) != 5 {
		t.Errorf("GetGeohash precision=5 returned length %d", len(h5))
	}
	if len(h7) != 7 {
		t.Errorf("GetGeohash precision=7 returned length %d", len(h7))
	}

	// Higher precision shares prefix with lower precision
	if !strings.HasPrefix(h5, h3) {
		t.Errorf("h5=%s does not start with h3=%s", h5, h3)
	}
	if !strings.HasPrefix(h7, h5) {
		t.Errorf("h7=%s does not start with h5=%s", h7, h5)
	}

	// Deterministic
	if h5 != GetGeohash(6.5244, 3.3792, 5) {
		t.Error("GetGeohash is not deterministic")
	}

	// Nearby coordinates share a prefix (spatial proximity)
	nearA := GetGeohash(6.5244, 3.3792, 5)
	nearB := GetGeohash(6.5245, 3.3793, 5) // ~11m away
	if nearA[:3] != nearB[:3] {
		t.Errorf("Nearby coords don't share 3-char prefix: %s vs %s", nearA, nearB)
	}

	// Distant coordinates differ
	farA := GetGeohash(6.5244, 3.3792, 5)  // Lagos
	farB := GetGeohash(51.5074, -0.1278, 5) // London
	if farA == farB {
		t.Error("Lagos and London should have different geohashes")
	}

	// Default precision when 0
	h0 := GetGeohash(6.5244, 3.3792, 0)
	if len(h0) != 5 {
		t.Errorf("GetGeohash precision=0 should default to 5, got length %d", len(h0))
	}

	// Uses only valid base32 characters
	validChars := "0123456789bcdefghjkmnpqrstuvwxyz"
	for _, c := range h5 {
		if !strings.ContainsRune(validChars, c) {
			t.Errorf("Invalid geohash character: %c in %s", c, h5)
		}
	}
}

func TestAnonymizeSignal(t *testing.T) {
	raw := RawData{
		ID:        "user-123",
		Name:      "John Doe",
		Account:   "ACC456",
		Amount:    1250.00,
		Latitude:  6.5244,
		Longitude: 3.3792,
		Timestamp: "2025-01-15T10:30:00Z",
	}

	t.Run("basic fields populated", func(t *testing.T) {
		sig := AnonymizeSignal(raw, "BNK_001", "salt", "pepper", 10000)

		if sig.InstitutionID != "BNK_001" {
			t.Errorf("InstitutionID = %s, want BNK_001", sig.InstitutionID)
		}
		if sig.SignalType != "transaction" {
			t.Errorf("SignalType = %s, want transaction", sig.SignalType)
		}
		if sig.IdentityMosaic == "" {
			t.Error("IdentityMosaic is empty")
		}
		if len(sig.IdentityMosaic) != 64 {
			t.Errorf("IdentityMosaic length = %d, want 64", len(sig.IdentityMosaic))
		}
		if sig.Timestamp != raw.Timestamp {
			t.Errorf("Timestamp = %s, want %s", sig.Timestamp, raw.Timestamp)
		}
		if sig.Metadata["amount_tier"] != "TIER_2" {
			t.Errorf("amount_tier = %v, want TIER_2", sig.Metadata["amount_tier"])
		}
		if sig.Metadata["location_zone"] == "" {
			t.Error("location_zone is empty")
		}
		if sig.Metadata["account_hash"] == "" {
			t.Error("account_hash is empty")
		}
	})

	t.Run("deterministic mosaic", func(t *testing.T) {
		s1 := AnonymizeSignal(raw, "BNK_001", "salt", "pepper", 10000)
		s2 := AnonymizeSignal(raw, "BNK_001", "salt", "pepper", 10000)
		if s1.IdentityMosaic != s2.IdentityMosaic {
			t.Error("Mosaic is not deterministic")
		}
	})

	t.Run("different salt produces different mosaic", func(t *testing.T) {
		s1 := AnonymizeSignal(raw, "BNK_001", "salt-a", "pepper", 10000)
		s2 := AnonymizeSignal(raw, "BNK_001", "salt-b", "pepper", 10000)
		if s1.IdentityMosaic == s2.IdentityMosaic {
			t.Error("Different salts produced same mosaic")
		}
	})

	t.Run("near threshold flag", func(t *testing.T) {
		// 9500 is exactly 95% of 10000 — should trigger
		nearRaw := raw
		nearRaw.Amount = 9500
		sig := AnonymizeSignal(nearRaw, "BNK_001", "salt", "pepper", 10000)
		if sig.Metadata["is_near_threshold"] != true {
			t.Error("Expected is_near_threshold=true for amount=9500, threshold=10000")
		}

		// 9499 is below 95% — should not trigger
		belowRaw := raw
		belowRaw.Amount = 9499
		sig2 := AnonymizeSignal(belowRaw, "BNK_001", "salt", "pepper", 10000)
		if _, exists := sig2.Metadata["is_near_threshold"]; exists {
			t.Error("Expected no is_near_threshold for amount=9499, threshold=10000")
		}
	})

	t.Run("device_id hashed", func(t *testing.T) {
		devRaw := raw
		devRaw.DeviceID = "device-001"
		sig := AnonymizeSignal(devRaw, "BNK_001", "salt", "pepper", 10000)
		if sig.Metadata["device_id_hash"] == "" {
			t.Error("device_id_hash should be set when DeviceID provided")
		}
		if sig.Metadata["device_id_hash"] == "device-001" {
			t.Error("device_id_hash should be hashed, not raw")
		}
	})

	t.Run("device_id_hash passthrough", func(t *testing.T) {
		devRaw := raw
		devRaw.DeviceIDHash = "pre-hashed-value"
		sig := AnonymizeSignal(devRaw, "BNK_001", "salt", "pepper", 10000)
		if sig.Metadata["device_id_hash"] != "pre-hashed-value" {
			t.Errorf("device_id_hash = %v, want pre-hashed-value", sig.Metadata["device_id_hash"])
		}
	})

	t.Run("counterparty creates destination_mosaic", func(t *testing.T) {
		cpRaw := raw
		cpRaw.CounterpartyID = "counterparty-xyz"
		sig := AnonymizeSignal(cpRaw, "BNK_001", "salt", "pepper", 10000)
		if sig.DestinationMosaic == "" {
			t.Error("DestinationMosaic should be set when CounterpartyID provided")
		}
		if len(sig.DestinationMosaic) != 64 {
			t.Errorf("DestinationMosaic length = %d, want 64", len(sig.DestinationMosaic))
		}
	})

	t.Run("empty institution defaults", func(t *testing.T) {
		sig := AnonymizeSignal(raw, "", "salt", "pepper", 10000)
		if sig.InstitutionID != "BNK_DEFAULT" {
			t.Errorf("InstitutionID = %s, want BNK_DEFAULT", sig.InstitutionID)
		}
	})

	t.Run("custom signal_type", func(t *testing.T) {
		customRaw := raw
		customRaw.SignalType = "transfer"
		sig := AnonymizeSignal(customRaw, "BNK_001", "salt", "pepper", 10000)
		if sig.SignalType != "transfer" {
			t.Errorf("SignalType = %s, want transfer", sig.SignalType)
		}
	})

	t.Run("branch_id and endpoint_type", func(t *testing.T) {
		brRaw := raw
		brRaw.BranchID = "LAG-01"
		brRaw.EndpointType = "ATM"
		sig := AnonymizeSignal(brRaw, "BNK_001", "salt", "pepper", 10000)
		if sig.Metadata["branch_id"] != "LAG-01" {
			t.Errorf("branch_id = %v, want LAG-01", sig.Metadata["branch_id"])
		}
		if sig.Metadata["endpoint_type"] != "ATM" {
			t.Errorf("endpoint_type = %v, want ATM", sig.Metadata["endpoint_type"])
		}
	})

	t.Run("ip hashing", func(t *testing.T) {
		ipRaw := raw
		ipRaw.IP = "192.168.1.1"
		sig := AnonymizeSignal(ipRaw, "BNK_001", "salt", "pepper", 10000)
		if sig.Metadata["ip_hash"] == "" {
			t.Error("ip_hash should be set when IP provided")
		}
		if sig.Metadata["ip_hash"] == "192.168.1.1" {
			t.Error("ip_hash should be hashed, not raw")
		}
	})

	t.Run("ip_hash passthrough", func(t *testing.T) {
		ipRaw := raw
		ipRaw.IPHash = "pre-hashed-ip"
		sig := AnonymizeSignal(ipRaw, "BNK_001", "salt", "pepper", 10000)
		if sig.Metadata["ip_hash"] != "pre-hashed-ip" {
			t.Errorf("ip_hash = %v, want pre-hashed-ip", sig.Metadata["ip_hash"])
		}
	})
}
