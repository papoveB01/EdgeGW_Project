package processor

import (
	"errors"
	"math"
	"strings"
	"testing"
)

func f64(v float64) *float64 { return &v }

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

	// Out-of-range coordinates return unknown
	if Geohash(91, 10.0, 5) != "ZONE_UNKNOWN" {
		t.Error("latitude > 90 should return ZONE_UNKNOWN")
	}
	if Geohash(45, 181, 5) != "ZONE_UNKNOWN" {
		t.Error("longitude > 180 should return ZONE_UNKNOWN")
	}
}

func TestBucketTimestamp(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"2026-01-15T14:07:33.123Z", "2026-01-15T14:00:00Z"},
		{"2026-01-15T14:14:59.999Z", "2026-01-15T14:00:00Z"},
		{"2026-01-15T14:15:00Z", "2026-01-15T14:15:00Z"},
		{"2026-01-15T14:29:33.123Z", "2026-01-15T14:15:00Z"},
		{"2026-01-15T14:44:33Z", "2026-01-15T14:30:00Z"},
		{"2026-01-15T14:59:33Z", "2026-01-15T14:45:00Z"},
		// Offsets are normalized to UTC so cross-institution timestamps compare
		{"2026-01-15T15:07:33+01:00", "2026-01-15T14:00:00Z"},
		{"2026-01-15T09:07:33-05:00", "2026-01-15T14:00:00Z"},
		// Garbage never passes through raw
		{"not-a-timestamp", "TIME_UNKNOWN"},
		{"2026-01-15T14:07:33", "TIME_UNKNOWN"}, // missing offset — not RFC 3339
		{"", "TIME_UNKNOWN"},
	}
	for _, tt := range tests {
		got := BucketTimestamp(tt.input)
		if got != tt.want {
			t.Errorf("BucketTimestamp(%s) = %s, want %s", tt.input, got, tt.want)
		}
	}
}

func TestValidate(t *testing.T) {
	valid := RawData{ID: "CUST-1", Name: "Test", Account: "ACC-1", Amount: 100,
		Latitude: f64(6.45), Longitude: f64(3.39), Timestamp: "2026-01-15T14:07:33Z"}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid data rejected: %v", err)
	}

	// Location is optional when omitted together
	noLoc := valid
	noLoc.Latitude, noLoc.Longitude = nil, nil
	if err := noLoc.Validate(); err != nil {
		t.Errorf("missing location should be allowed: %v", err)
	}

	cases := []struct {
		name   string
		mutate func(*RawData)
	}{
		{"empty id", func(r *RawData) { r.ID = "" }},
		{"whitespace id", func(r *RawData) { r.ID = "   " }},
		{"empty name", func(r *RawData) { r.Name = "" }},
		{"empty account", func(r *RawData) { r.Account = "" }},
		{"zero amount", func(r *RawData) { r.Amount = 0 }},
		{"negative amount", func(r *RawData) { r.Amount = -50 }},
		{"bad timestamp", func(r *RawData) { r.Timestamp = "yesterday" }},
		{"no-offset timestamp", func(r *RawData) { r.Timestamp = "2026-01-15T14:07:33" }},
		{"lat without lon", func(r *RawData) { r.Longitude = nil }},
		{"lat out of range", func(r *RawData) { r.Latitude = f64(95) }},
		{"lon out of range", func(r *RawData) { r.Longitude = f64(-190) }},
		{"unknown signal_type", func(r *RawData) { r.SignalType = "behavioural_profile" }},
		{"unknown endpoint_type", func(r *RawData) { r.EndpointType = "SMART_FRIDGE" }},
	}
	for _, tc := range cases {
		r := valid
		tc.mutate(&r)
		if err := r.Validate(); err == nil {
			t.Errorf("%s: expected validation error, got nil", tc.name)
		}
	}
}

func TestAnonymizeSignal_BankKeyingMosaicDiffersAcrossBanks(t *testing.T) {
	// KeyingBank is the default and MUST NOT allow two different banks
	// (different BANK_SALT) to derive the same mosaic for the same person,
	// even when they share a pepper and even for the SAME national ID. This
	// replaces the old (pre-v3) TestAnonymizeSignal_GlobalMosaicCrossBank,
	// whose premise (same national ID -> same mosaic across banks, with no
	// bank secret involved) is exactly the enumerable-mosaic-table risk this
	// change closes.
	atBankA := RawData{ID: "CUST-001", Name: "John Doe", NationalID: "22345678901",
		Account: "ACC-A", Amount: 100, Timestamp: "2026-01-01T00:00:00Z"}
	atBankB := RawData{ID: "CIF-99887", Name: "DOE, JOHN", NationalID: "2234-5678 901",
		Account: "ACC-B", Amount: 100, Timestamp: "2026-01-01T00:00:00Z"}

	sigA := AnonymizeSignal(atBankA, "BNK_A", "salt_a", "shared_pepper", KeyingBank, 10000, "fallback-id")
	sigB := AnonymizeSignal(atBankB, "BNK_B", "salt_b", "shared_pepper", KeyingBank, 10000, "fallback-id")

	if sigA.IdentityMosaic == sigB.IdentityMosaic {
		t.Error("bank-keyed mosaics for the same national ID must differ across banks with different BANK_SALT")
	}
	if sigA.MosaicScope != ScopeBank || sigB.MosaicScope != ScopeBank {
		t.Errorf("expected bank scope, got %s / %s", sigA.MosaicScope, sigB.MosaicScope)
	}
	if sigA.MosaicBasis != BasisNationalID || sigB.MosaicBasis != BasisNationalID {
		t.Errorf("expected national_id basis, got %s / %s", sigA.MosaicBasis, sigB.MosaicBasis)
	}
	if sigA.MosaicVersion != MosaicVersion {
		t.Errorf("expected mosaic version %d, got %d", MosaicVersion, sigA.MosaicVersion)
	}

	// Same bank, same identity, but WITHOUT a shared pepper must still
	// reproduce the same mosaic as WITH one dropped on the other side, as
	// long as salt matches - the point of bank mode is that BANK_SALT alone
	// is sufficient. Demonstrate the opposite too: a different pepper with
	// the same salt still changes the mosaic (defense in depth).
	sigNoPepper := AnonymizeSignal(atBankA, "BNK_A", "salt_a", "", KeyingBank, 10000, "fallback-id")
	if sigNoPepper.IdentityMosaic == sigA.IdentityMosaic {
		t.Error("dropping the pepper (with the same salt) must change the mosaic - pepper is folded in as additional key material when present")
	}

	sigOtherPepper := AnonymizeSignal(atBankA, "BNK_A", "salt_a", "other_pepper", KeyingBank, 10000, "fallback-id")
	if sigOtherPepper.IdentityMosaic == sigA.IdentityMosaic {
		t.Error("expected sanity: different pepper values should be exercised as different mosaics")
	}

	// Different salt alone (pepper empty on both sides) must still change
	// the mosaic - BANK_SALT is what protects a bank-keyed mosaic when no
	// pepper is configured at all.
	sigA2 := AnonymizeSignal(atBankA, "BNK_A", "salt_a", "", KeyingBank, 10000, "fallback-id")
	sigB2 := AnonymizeSignal(atBankA, "BNK_A", "salt_b_different", "", KeyingBank, 10000, "fallback-id")
	if sigA2.IdentityMosaic == sigB2.IdentityMosaic {
		t.Error("different BANK_SALT with no pepper configured must still produce different mosaics")
	}
}

func TestAnonymizeSignal_RegionalKeyingMosaicIdenticalAcrossBanks(t *testing.T) {
	// KeyingRegional is the opt-in mode that intentionally preserves the old
	// cross-gateway-derivable behavior: same national ID + same shared
	// pepper must produce the SAME mosaic regardless of each bank's own
	// salt or internal customer ID. This is the companion to
	// TestAnonymizeSignal_BankKeyingMosaicDiffersAcrossBanks, proving the two
	// modes are genuinely different and that regional mode still works as
	// documented for its intended future remote-gateway use case.
	atBankA := RawData{ID: "CUST-001", Name: "John Doe", NationalID: "22345678901",
		Account: "ACC-A", Amount: 100, Timestamp: "2026-01-01T00:00:00Z"}
	atBankB := RawData{ID: "CIF-99887", Name: "DOE, JOHN", NationalID: "2234-5678 901",
		Account: "ACC-B", Amount: 100, Timestamp: "2026-01-01T00:00:00Z"}

	sigA := AnonymizeSignal(atBankA, "BNK_A", "salt_a", "shared_pepper", KeyingRegional, 10000, "fallback-id")
	sigB := AnonymizeSignal(atBankB, "BNK_B", "salt_b", "shared_pepper", KeyingRegional, 10000, "fallback-id")

	if sigA.IdentityMosaic != sigB.IdentityMosaic {
		t.Error("regional-keyed mosaics for the same national ID and shared pepper must be identical across banks")
	}
	if sigA.MosaicScope != ScopeRegional || sigB.MosaicScope != ScopeRegional {
		t.Errorf("expected regional scope, got %s / %s", sigA.MosaicScope, sigB.MosaicScope)
	}
	if sigA.MosaicBasis != BasisNationalID {
		t.Errorf("expected national_id basis, got %s", sigA.MosaicBasis)
	}

	// Different pepper must still produce a different mosaic (pepper is the
	// sole key in regional mode).
	sigC := AnonymizeSignal(atBankA, "BNK_A", "salt_a", "other_pepper", KeyingRegional, 10000, "fallback-id")
	if sigC.IdentityMosaic == sigA.IdentityMosaic {
		t.Error("different pepper must change the regional mosaic")
	}

	// A different bank salt must NOT change the mosaic in regional mode -
	// that's the entire point of the mode (BANK_SALT is deliberately not
	// part of the key here).
	sigDifferentSaltSamePepper := AnonymizeSignal(atBankA, "BNK_A", "totally_different_salt", "shared_pepper", KeyingRegional, 10000, "fallback-id")
	if sigDifferentSaltSamePepper.IdentityMosaic != sigA.IdentityMosaic {
		t.Error("regional mode must ignore BANK_SALT entirely for the national-ID mosaic")
	}
}

func TestAnonymizeSignal_LocalFallbackAlwaysBankScopedRegardlessOfKeying(t *testing.T) {
	// Without a national ID the mosaic falls back to internal ID + name. It
	// must always fold in BANK_SALT and always report ScopeBank / a
	// BasisInternalIDFallback basis - regardless of the configured
	// MosaicKeying - because it has no cross-gateway meaning even in
	// regional mode (it's tied to this bank's own internal identifiers).
	raw1 := RawData{ID: "CUST-001", Name: "John Doe", Account: "A", Amount: 100, Timestamp: "2026-01-01T00:00:00Z"}
	raw2 := RawData{ID: "cust-001", Name: "  JOHN   DOE ", Account: "A", Amount: 100, Timestamp: "2026-01-01T00:00:00Z"}

	for _, keying := range []string{KeyingBank, KeyingRegional} {
		sig1 := AnonymizeSignal(raw1, "BNK", "salt", "pepper", keying, 10000, "fallback-id")
		sig2 := AnonymizeSignal(raw2, "BNK", "salt", "pepper", keying, 10000, "fallback-id")

		if sig1.MosaicScope != ScopeBank {
			t.Errorf("keying=%s: expected ScopeBank for the local fallback, got %s", keying, sig1.MosaicScope)
		}
		if sig1.MosaicBasis != BasisInternalIDFallback {
			t.Errorf("keying=%s: expected BasisInternalIDFallback, got %s", keying, sig1.MosaicBasis)
		}
		if sig1.IdentityMosaic != sig2.IdentityMosaic {
			t.Errorf("keying=%s: normalization should make casing/spacing variants produce the same fallback mosaic", keying)
		}
	}

	// Different salts (different banks) must produce different fallback
	// mosaics, regardless of keying mode.
	sig1 := AnonymizeSignal(raw1, "BNK", "salt", "pepper", KeyingBank, 10000, "fallback-id")
	sig3 := AnonymizeSignal(raw1, "BNK2", "other_salt", "pepper", KeyingBank, 10000, "fallback-id")
	if sig3.IdentityMosaic == sig1.IdentityMosaic {
		t.Error("fallback mosaics must differ across banks (different salts)")
	}
}

func TestAnonymizeSignal_UnrecognizedKeyingFailsSafeToBank(t *testing.T) {
	// An unrecognized keying value must not fall through to the more
	// dangerous regional (pepper-alone) derivation - AnonymizeSignal treats
	// anything other than exactly KeyingRegional as KeyingBank.
	raw := RawData{ID: "1", Name: "Test", NationalID: "22345678901", Account: "ACC", Amount: 100, Timestamp: "2026-01-01T00:00:00Z"}

	sigUnknown := AnonymizeSignal(raw, "BNK", "salt", "pepper", "not-a-real-mode", 10000, "fallback-id")
	sigBank := AnonymizeSignal(raw, "BNK", "salt", "pepper", KeyingBank, 10000, "fallback-id")
	sigRegional := AnonymizeSignal(raw, "BNK", "salt", "pepper", KeyingRegional, 10000, "fallback-id")

	if sigUnknown.IdentityMosaic != sigBank.IdentityMosaic || sigUnknown.MosaicScope != ScopeBank {
		t.Error("unrecognized MosaicKeying value must behave exactly like KeyingBank")
	}
	if sigUnknown.IdentityMosaic == sigRegional.IdentityMosaic {
		t.Error("unrecognized MosaicKeying value must not accidentally match the regional derivation")
	}
}

func TestAnonymizeSignal_DestinationMatchesIdentity(t *testing.T) {
	sender := RawData{ID: "S", Name: "Sender", Account: "A1", Amount: 100, Timestamp: "2026-01-01T00:00:00Z",
		CounterpartyID: "CP-1", CounterpartyNationalID: "99887766554"}
	counterpartyOwnTxn := RawData{ID: "CP-1", Name: "Mule Person", NationalID: "99887766554",
		Account: "A2", Amount: 50, Timestamp: "2026-01-01T00:00:00Z"}

	// Bank mode, SAME institution: route-following within one bank must
	// still work — sender and counterparty share BANK_SALT, so the
	// destination mosaic (keyed with the sender's own salt) equals the
	// mosaic the counterparty derives for their own transaction (keyed with
	// that same salt, since it's the same bank).
	sentSameBank := AnonymizeSignal(sender, "BNK_A", "salt_a", "pepper", KeyingBank, 10000, "fallback-id")
	ownSameBank := AnonymizeSignal(counterpartyOwnTxn, "BNK_A", "salt_a", "pepper", KeyingBank, 10000, "fallback-id")
	if sentSameBank.DestinationMosaic != ownSameBank.IdentityMosaic {
		t.Error("bank-scoped destination mosaic must match the counterparty's own identity mosaic when produced by the SAME institution (same BANK_SALT)")
	}
	if sentSameBank.DestinationMosaicScope != ScopeBank {
		t.Errorf("expected bank destination scope, got %s", sentSameBank.DestinationMosaicScope)
	}
	if sentSameBank.DestinationMosaicBasis != BasisNationalID {
		t.Errorf("expected national_id destination basis, got %s", sentSameBank.DestinationMosaicBasis)
	}

	// Bank mode, DIFFERENT institutions: this is the whole point of
	// bank-scoping — a destination mosaic computed with the sender's own
	// BANK_SALT must NOT match an identity mosaic the counterparty's own
	// (different) bank derived with ITS salt. Cross-bank route-following
	// does not work in bank mode, by design.
	sentOtherBank := AnonymizeSignal(sender, "BNK_A", "salt_a", "pepper", KeyingBank, 10000, "fallback-id")
	ownOtherBank := AnonymizeSignal(counterpartyOwnTxn, "BNK_B", "salt_b", "pepper", KeyingBank, 10000, "fallback-id")
	if sentOtherBank.DestinationMosaic == ownOtherBank.IdentityMosaic {
		t.Error("bank-scoped destination/identity mosaics must NOT match across different institutions (different BANK_SALT) - that cross-gateway comparability is exactly what bank scoping removes")
	}

	// Regional mode: the national-ID branch is keyed on the pepper alone,
	// so cross-institution route-following is preserved exactly as before —
	// this is the documented use case for opting into regional keying.
	sentRegional := AnonymizeSignal(sender, "BNK_A", "salt_a", "pepper", KeyingRegional, 10000, "fallback-id")
	ownRegional := AnonymizeSignal(counterpartyOwnTxn, "BNK_B", "salt_b", "pepper", KeyingRegional, 10000, "fallback-id")
	if sentRegional.DestinationMosaic != ownRegional.IdentityMosaic {
		t.Error("regional-scoped destination mosaic must match the counterparty's own identity mosaic across institutions")
	}
	if sentRegional.DestinationMosaicScope != ScopeRegional {
		t.Errorf("expected regional destination scope, got %s", sentRegional.DestinationMosaicScope)
	}
}

func TestNormalize(t *testing.T) {
	if NormalizeID("2234-5678 901") != "22345678901" {
		t.Errorf("NormalizeID should strip separators: %q", NormalizeID("2234-5678 901"))
	}
	if NormalizeID("abc.123") != "ABC123" {
		t.Errorf("NormalizeID should uppercase and strip dots: %q", NormalizeID("abc.123"))
	}
	if NormalizeName("  john   Doe ") != "JOHN DOE" {
		t.Errorf("NormalizeName should collapse whitespace and uppercase: %q", NormalizeName("  john   Doe "))
	}
}

func TestAnonymizeSignal_FieldDelimiters(t *testing.T) {
	// Two different identity inputs that would collide without delimiters
	raw1 := RawData{ID: "ab", Name: "cd", Account: "1234", Amount: 100, Timestamp: "2026-01-01T00:00:00Z"}
	raw2 := RawData{ID: "a", Name: "bcd", Account: "1234", Amount: 100, Timestamp: "2026-01-01T00:00:00Z"}

	sig1 := AnonymizeSignal(raw1, "BNK", "salt", "pepper", KeyingBank, 10000, "fallback-id")
	sig2 := AnonymizeSignal(raw2, "BNK", "salt", "pepper", KeyingBank, 10000, "fallback-id")

	if sig1.IdentityMosaic == sig2.IdentityMosaic {
		t.Error("field delimiter collision: different inputs produced same mosaic")
	}
}

func TestAnonymizeSignal_NearThreshold(t *testing.T) {
	raw := RawData{ID: "1", Name: "Test", Account: "ACC", Amount: 9600, Timestamp: "2026-01-01T00:00:00Z"}
	sig := AnonymizeSignal(raw, "BNK", "salt", "pepper", KeyingBank, 10000, "fallback-id")

	if _, ok := sig.Metadata["is_near_threshold"]; !ok {
		t.Error("expected is_near_threshold flag for 9600 with threshold 10000")
	}

	raw.Amount = 9000
	sig = AnonymizeSignal(raw, "BNK", "salt", "pepper", KeyingBank, 10000, "fallback-id")
	if _, ok := sig.Metadata["is_near_threshold"]; ok {
		t.Error("should not flag 9000 as near threshold")
	}
}

func TestAnonymizeSignal_MissingLocation(t *testing.T) {
	raw := RawData{ID: "1", Name: "Test", Account: "ACC", Amount: 100, Timestamp: "2026-01-01T00:00:00Z"}
	sig := AnonymizeSignal(raw, "BNK", "salt", "pepper", KeyingBank, 10000, "fallback-id")

	if sig.Metadata["location_zone"] != "ZONE_UNKNOWN" {
		t.Errorf("missing location should map to ZONE_UNKNOWN, got %v", sig.Metadata["location_zone"])
	}
}

func TestAnonymizeSignal_DestinationMosaic(t *testing.T) {
	raw := RawData{ID: "1", Name: "Test", Account: "ACC", Amount: 100, Timestamp: "2026-01-01T00:00:00Z", CounterpartyID: "CP123"}
	sig := AnonymizeSignal(raw, "BNK", "salt", "pepper", KeyingBank, 10000, "fallback-id")

	if sig.DestinationMosaic == "" {
		t.Error("expected destination_mosaic when counterparty_id is set")
	}
	if sig.DestinationMosaicScope != ScopeBank {
		t.Errorf("counterparty_id without national ID should be bank scope, got %s", sig.DestinationMosaicScope)
	}
	if sig.DestinationMosaicBasis != BasisInternalIDFallback {
		t.Errorf("counterparty_id without national ID should be internal_id_fallback basis, got %s", sig.DestinationMosaicBasis)
	}
}

func TestAnonymizeSignal_DeviceAndIPHash(t *testing.T) {
	raw := RawData{ID: "1", Name: "Test", Account: "ACC", Amount: 100, Timestamp: "2026-01-01T00:00:00Z",
		DeviceID: "device123", IP: "192.168.1.1"}
	sig := AnonymizeSignal(raw, "BNK", "salt", "pepper", KeyingBank, 10000, "fallback-id")

	if _, ok := sig.Metadata["device_id_hash"]; !ok {
		t.Error("expected device_id_hash")
	}
	if _, ok := sig.Metadata["ip_hash"]; !ok {
		t.Error("expected ip_hash")
	}

	// Pre-hashed should pass through
	raw2 := RawData{ID: "1", Name: "Test", Account: "ACC", Amount: 100, Timestamp: "2026-01-01T00:00:00Z",
		DeviceIDHash: "prehashed_device", IPHash: "prehashed_ip"}
	sig2 := AnonymizeSignal(raw2, "BNK", "salt", "pepper", KeyingBank, 10000, "fallback-id")

	if sig2.Metadata["device_id_hash"] != "prehashed_device" {
		t.Error("pre-hashed device_id_hash should pass through")
	}
	if sig2.Metadata["ip_hash"] != "prehashed_ip" {
		t.Error("pre-hashed ip_hash should pass through")
	}
}

func TestAnonymizeSignal_AccountDeviceIPHashUseVersionedHMAC(t *testing.T) {
	// account_hash/device_id_hash/ip_hash must use HMACHash(salt, "v3|<field>|"+value)
	// — a keyed MAC with an explicit versioned domain tag — not the older
	// plain Hash(value+"|"+salt) concatenation-hash construction. Assert the
	// exact formula so a regression back to the weaker construction (which
	// would still produce SOME 64-char hex string and pass a shallow
	// "is it hashed" check) is caught.
	raw := RawData{ID: "1", Name: "Test", Account: "ACC-123", Amount: 100, Timestamp: "2026-01-01T00:00:00Z",
		DeviceID: "device123", IP: "192.168.1.1"}
	sig := AnonymizeSignal(raw, "BNK", "salt", "pepper", KeyingBank, 10000, "fallback-id")

	wantAccount := HMACHash("salt", "v3|account|ACC-123")
	wantDevice := HMACHash("salt", "v3|device|device123")
	wantIP := HMACHash("salt", "v3|ip|192.168.1.1")

	if sig.Metadata["account_hash"] != wantAccount {
		t.Errorf("account_hash = %v, want %v (HMACHash(salt, \"v3|account|\"+account))", sig.Metadata["account_hash"], wantAccount)
	}
	if sig.Metadata["device_id_hash"] != wantDevice {
		t.Errorf("device_id_hash = %v, want %v (HMACHash(salt, \"v3|device|\"+device_id))", sig.Metadata["device_id_hash"], wantDevice)
	}
	if sig.Metadata["ip_hash"] != wantIP {
		t.Errorf("ip_hash = %v, want %v (HMACHash(salt, \"v3|ip|\"+ip))", sig.Metadata["ip_hash"], wantIP)
	}

	// Sanity: must NOT match the old plain-concatenation SHA-256 construction.
	oldAccount := Hash(raw.Account + "|" + "salt")
	if sig.Metadata["account_hash"] == oldAccount {
		t.Error("account_hash must not use the old Hash(value+\"|\"+salt) construction")
	}
}

func TestValidate_SignalTypeAllowlist(t *testing.T) {
	base := RawData{ID: "1", Name: "Test", Account: "ACC", Amount: 100, Timestamp: "2026-01-15T14:07:33Z"}

	tests := []struct {
		name       string
		signalType string
		wantErr    bool
	}{
		{"empty defaults, allowed", "", false},
		{"known: transaction", "transaction", false},
		{"known: login", "login", false},
		{"known: transfer", "transfer", false},
		{"known: authentication", "authentication", false},
		{"unknown value rejected", "general_behaviour", true},
		// Matching is case-insensitive (see TestValidate_SignalTypeCaseInsensitiveNormalization
		// for the normalization assertion) — mixed case of a KNOWN value is accepted.
		{"mixed case of known value accepted", "Transaction", false},
		{"unknown value still rejected regardless of case", "General_Behaviour", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := base
			r.SignalType = tt.signalType
			err := r.Validate()
			if tt.wantErr && err == nil {
				t.Errorf("signal_type %q: expected validation error, got nil", tt.signalType)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("signal_type %q: unexpected validation error: %v", tt.signalType, err)
			}
			if tt.wantErr {
				var ve *ValidationError
				if !isValidationError(err, &ve) {
					t.Fatalf("signal_type %q: expected *ValidationError, got %T", tt.signalType, err)
				}
				if ve.Field != "signal_type" {
					t.Errorf("signal_type %q: expected error field %q, got %q", tt.signalType, "signal_type", ve.Field)
				}
			}
		})
	}
}

func TestValidate_EndpointTypeAllowlist(t *testing.T) {
	base := RawData{ID: "1", Name: "Test", Account: "ACC", Amount: 100, Timestamp: "2026-01-15T14:07:33Z"}

	tests := []struct {
		name         string
		endpointType string
		wantErr      bool
	}{
		{"empty is allowed", "", false},
		{"known: MOBILE_APP", "MOBILE_APP", false},
		{"known: ATM", "ATM", false},
		{"known: POS", "POS", false},
		{"known: WEB", "WEB", false},
		{"known: BRANCH", "BRANCH", false},
		{"known: API", "API", false},
		{"known: USSD", "USSD", false},
		{"known: IVR", "IVR", false},
		{"unknown value rejected", "SMART_FRIDGE", true},
		// Matching is case-insensitive (see TestValidate_EndpointTypeCaseInsensitiveNormalization
		// for the normalization assertion) — mixed case of a KNOWN value is accepted.
		{"mixed case of known value accepted", "mobile_app", false},
		{"unknown value still rejected regardless of case", "smart_fridge", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := base
			r.EndpointType = tt.endpointType
			err := r.Validate()
			if tt.wantErr && err == nil {
				t.Errorf("endpoint_type %q: expected validation error, got nil", tt.endpointType)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("endpoint_type %q: unexpected validation error: %v", tt.endpointType, err)
			}
			if tt.wantErr {
				var ve *ValidationError
				if !isValidationError(err, &ve) {
					t.Fatalf("endpoint_type %q: expected *ValidationError, got %T", tt.endpointType, err)
				}
				if ve.Field != "endpoint_type" {
					t.Errorf("endpoint_type %q: expected error field %q, got %q", tt.endpointType, "endpoint_type", ve.Field)
				}
			}
		})
	}
}

// isValidationError type-asserts err into a *ValidationError, storing it into
// *out and reporting whether the assertion succeeded.
func isValidationError(err error, out **ValidationError) bool {
	ve, ok := err.(*ValidationError)
	if ok {
		*out = ve
	}
	return ok
}

// TestAnonymizeSignal_SignalIDUniqueAcrossCalls exercises the realistic
// pipeline end to end: the caller generates a fresh fallbackSignalID per
// request via NewSignalID() (as processTransaction does) and AnonymizeSignal
// uses it verbatim. Uniqueness across calls with identical RawData now comes
// entirely from that caller-side generation, not from anything AnonymizeSignal
// does internally - it is a pure pass-through, see its doc comment.
func TestAnonymizeSignal_SignalIDUniqueAcrossCalls(t *testing.T) {
	raw := RawData{ID: "1", Name: "Test", Account: "ACC", Amount: 100, Timestamp: "2026-01-01T00:00:00Z"}

	seen := make(map[string]bool)
	const n = 200
	for i := 0; i < n; i++ {
		fallbackID, err := NewSignalID()
		if err != nil {
			t.Fatalf("NewSignalID: unexpected error from a healthy entropy source: %v", err)
		}
		sig := AnonymizeSignal(raw, "BNK", "salt", "pepper", KeyingBank, 10000, fallbackID)
		if sig.SignalID == "" {
			t.Fatal("expected a non-empty signal_id")
		}
		if sig.SignalID != fallbackID {
			t.Fatalf("expected AnonymizeSignal to pass fallbackSignalID through verbatim, got %q for input %q", sig.SignalID, fallbackID)
		}
		if seen[sig.SignalID] {
			t.Fatalf("signal_id collision across calls: %s", sig.SignalID)
		}
		seen[sig.SignalID] = true
	}

	// Not derived from PII: identical input, different national ID must not
	// change the fact that every call still gets its own fresh signal_id
	// (already covered above), and the identity mosaic (which IS derived
	// from PII/config) must differ from the signal_id in shape/value.
	sig := AnonymizeSignal(raw, "BNK", "salt", "pepper", KeyingBank, 10000, "fallback-id")
	if sig.SignalID == sig.IdentityMosaic {
		t.Error("signal_id must not equal identity_mosaic")
	}
}

func TestAnonymizeSignal_SignalIDDerivedFromCallerRef(t *testing.T) {
	// signal_id must be DERIVED from a caller-supplied transaction_ref, never
	// the raw value itself — the raw ref is forwarded to an external vendor
	// with no hashing anywhere else in the payload, and a format check alone
	// (transactionRefPattern) cannot distinguish an opaque reference from a
	// bare BVN/NIN, NUBAN account number, phone number, or a name with
	// separators stripped.
	ref := "core-banking-ref-88421"
	raw := RawData{ID: "1", Name: "Test", Account: "ACC", Amount: 100, Timestamp: "2026-01-01T00:00:00Z",
		TransactionRef: ref}

	sig := AnonymizeSignal(raw, "BNK", "salt", "pepper", KeyingBank, 10000, "fallback-id")
	if sig.SignalID == ref {
		t.Fatalf("signal_id must never equal the raw transaction_ref, got %q", sig.SignalID)
	}
	if sig.SignalID == "" {
		t.Fatal("expected a non-empty derived signal_id")
	}

	// Determinism: the same ref (and same salt) must derive the same
	// signal_id every time, so it still works as an idempotency key / join
	// key the bank can recompute.
	sigAgain := AnonymizeSignal(raw, "BNK", "salt", "pepper", KeyingBank, 10000, "fallback-id")
	if sig.SignalID != sigAgain.SignalID {
		t.Errorf("expected deterministic signal_id for the same ref, got %q and %q", sig.SignalID, sigAgain.SignalID)
	}

	// A different bank salt must change the derived signal_id — the vendor,
	// without BANK_SALT, must not be able to invert or correlate it.
	sigOtherSalt := AnonymizeSignal(raw, "BNK", "other_salt", "pepper", KeyingBank, 10000, "fallback-id")
	if sigOtherSalt.SignalID == sig.SignalID {
		t.Error("different bank salt must change the derived signal_id")
	}

	// Whitespace-only ref is treated as absent, same as the other optional
	// string fields' "must be usable, not just present" validation style:
	// AnonymizeSignal falls back to fallbackSignalID verbatim.
	rawBlank := raw
	rawBlank.TransactionRef = "   "
	sigBlank := AnonymizeSignal(rawBlank, "BNK", "salt", "pepper", KeyingBank, 10000, "fallback-id")
	if sigBlank.SignalID != "fallback-id" {
		t.Errorf("blank transaction_ref should fall back to fallbackSignalID verbatim, got %q", sigBlank.SignalID)
	}

	// AnonymizeSignal is a pure function of ALL its inputs, including
	// fallbackSignalID: it does not generate randomness itself (that is now
	// the caller's job, normally via NewSignalID() - see AnonymizeSignal's
	// doc comment and processTransaction in cmd/gateway/main.go). So two
	// calls with no ref but the SAME fallbackSignalID must agree...
	rawNoRef := raw
	rawNoRef.TransactionRef = ""
	sigA := AnonymizeSignal(rawNoRef, "BNK", "salt", "pepper", KeyingBank, 10000, "fallback-id-1")
	sigA2 := AnonymizeSignal(rawNoRef, "BNK", "salt", "pepper", KeyingBank, 10000, "fallback-id-1")
	if sigA.SignalID != sigA2.SignalID {
		t.Errorf("AnonymizeSignal must be pure/deterministic given the same fallbackSignalID, got %q and %q", sigA.SignalID, sigA2.SignalID)
	}
	if sigA.SignalID != "fallback-id-1" {
		t.Errorf("expected fallbackSignalID to be used verbatim as signal_id, got %q", sigA.SignalID)
	}

	// ...while a DIFFERENT fallbackSignalID (what two real calls would get,
	// since the caller generates a fresh one per request via NewSignalID())
	// must produce a different signal_id, and must not collide with the
	// derived signal_id above.
	sigB := AnonymizeSignal(rawNoRef, "BNK", "salt", "pepper", KeyingBank, 10000, "fallback-id-2")
	if sigA.SignalID == sigB.SignalID {
		t.Error("different fallbackSignalID values must produce different signal_id values")
	}
	if sigA.SignalID == sig.SignalID || sigB.SignalID == sig.SignalID {
		t.Error("fallback signal_id must not collide with a derived signal_id")
	}
}

func TestAnonymizeSignal_SignalIDDerivationHidesStructuredPII(t *testing.T) {
	// transactionRefPattern only screens obviously malformed input; these
	// values all pass that regex cleanly despite being structured PII
	// (BVN/NIN-shaped, NUBAN-account-shaped, phone-shaped, name-shaped).
	// The derivation step, not the regex, is what must keep them from
	// reaching the vendor verbatim.
	piiShapedRefs := []struct {
		name string
		ref  string
	}{
		{"BVN-shaped (11 digits)", "22345678901"},
		{"NUBAN account-shaped (10 digits)", "0123456789"},
		{"phone-shaped", "2348012345678"},
		{"name with space removed", "NgoziAdeyemi"},
		{"name with underscore", "Ngozi_Adeyemi"},
	}

	for _, tt := range piiShapedRefs {
		t.Run(tt.name, func(t *testing.T) {
			raw := RawData{ID: "1", Name: "Test", Account: "ACC", Amount: 100, Timestamp: "2026-01-01T00:00:00Z",
				TransactionRef: tt.ref}

			// Confirm the harness assumption: this value passes the input
			// hygiene regex, so the derivation step is the only thing
			// standing between it and the vendor.
			if !transactionRefPattern.MatchString(tt.ref) {
				t.Fatalf("test setup error: %q was expected to match transactionRefPattern", tt.ref)
			}

			sig := AnonymizeSignal(raw, "BNK", "salt", "pepper", KeyingBank, 10000, "fallback-id")
			if sig.SignalID == tt.ref {
				t.Errorf("PII-shaped transaction_ref %q must be transformed, not passed through, got signal_id %q", tt.ref, sig.SignalID)
			}
			if strings.Contains(sig.SignalID, tt.ref) {
				t.Errorf("derived signal_id %q must not contain the raw ref %q", sig.SignalID, tt.ref)
			}
		})
	}
}

func TestAnonymizeSignal_SignalIDDerivationIsExactBytesNotNormalized(t *testing.T) {
	// signal_id must be derived from the EXACT trimmed bytes of
	// transaction_ref, not NormalizeID's uppercased/separator-stripped
	// form. NormalizeID exists to converge inconsistently-formatted
	// national IDs onto one mosaic — the opposite of what an opaque
	// caller reference needs: two distinct references must never collide
	// onto the same signal_id, so case and punctuation must be
	// significant. Without this, "TX-001", "TX.001", "tx001" and "TX001"
	// would all derive the same signal_id despite being (potentially)
	// four different transactions, breaking both the out-of-band join and
	// idempotency in the wrong direction.
	mkSig := func(ref string) AnonymizedSignal {
		raw := RawData{ID: "1", Name: "Test", Account: "ACC", Amount: 100, Timestamp: "2026-01-01T00:00:00Z",
			TransactionRef: ref}
		return AnonymizeSignal(raw, "BNK", "salt", "pepper", KeyingBank, 10000, "fallback-id")
	}

	base := mkSig("TX001")

	tests := []struct {
		name string
		ref  string
	}{
		{"differs only by case", "tx001"},
		{"differs only by a dash", "TX-001"},
		{"differs only by a dot", "TX.001"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sig := mkSig(tt.ref)
			if sig.SignalID == base.SignalID {
				t.Errorf("transaction_ref %q must derive a DIFFERENT signal_id than %q, both got %q", tt.ref, "TX001", sig.SignalID)
			}
		})
	}

	// Sanity check the derivation formula directly: exact trimmed bytes,
	// not NormalizeID(ref).
	want := HMACHash("salt", "v2|sigid|TX001")
	if base.SignalID != want {
		t.Errorf("expected signal_id derived from exact bytes %q, got %q, want %q", "TX001", base.SignalID, want)
	}
}

func TestNewSignalID(t *testing.T) {
	a, err := NewSignalID()
	if err != nil {
		t.Fatalf("NewSignalID: unexpected error from a healthy entropy source: %v", err)
	}
	b, err := NewSignalID()
	if err != nil {
		t.Fatalf("NewSignalID: unexpected error from a healthy entropy source: %v", err)
	}
	if a == b {
		t.Fatal("NewSignalID must not repeat across calls")
	}
	// UUIDv4 shape: 8-4-4-4-12 hex, version nibble 4, variant nibble 8-b.
	if len(a) != 36 {
		t.Fatalf("expected 36-char UUID-shaped id, got %d: %q", len(a), a)
	}
	if a[14] != '4' {
		t.Errorf("expected UUID version nibble '4', got %q in %q", a[14], a)
	}
	if a[19] != '8' && a[19] != '9' && a[19] != 'a' && a[19] != 'b' {
		t.Errorf("expected UUID variant nibble in [89ab], got %q in %q", a[19], a)
	}
}

// TestNewSignalID_EntropyFailureReturnsErrorNotPanic is the mutation-tested
// regression guard for issue #4: NewSignalID must surface a broken entropy
// source as an error, never a panic, so callers (processTransaction) can
// turn it into a structured log + metric + proper HTTP status instead of a
// bare connection reset. It goes through newSignalIDFrom directly so the
// failure is injected via a plain func literal - no patched globals, no
// unsafe tricks, no real dependence on crypto/rand actually failing.
func TestNewSignalID_EntropyFailureReturnsErrorNotPanic(t *testing.T) {
	wantErr := errors.New("simulated CSPRNG failure")
	failingRead := func(b []byte) (int, error) { return 0, wantErr }

	id, err := newSignalIDFrom(failingRead)
	if err == nil {
		t.Fatal("expected an error when the entropy source fails, got nil")
	}
	if !errors.Is(err, wantErr) {
		t.Errorf("expected the returned error to wrap the underlying entropy error, got %v", err)
	}
	if id != "" {
		t.Errorf("expected an empty id on failure, got %q", id)
	}
}

func TestAnonymizeSignal_FeatureVersionEmitted(t *testing.T) {
	raw := RawData{ID: "1", Name: "Test", Account: "ACC", Amount: 100, Timestamp: "2026-01-01T00:00:00Z"}
	sig := AnonymizeSignal(raw, "BNK", "salt", "pepper", KeyingBank, 10000, "fallback-id")

	if sig.FeatureVersion != FeatureVersion {
		t.Errorf("expected feature_version %d, got %d", FeatureVersion, sig.FeatureVersion)
	}
	if sig.FeatureVersion == 0 {
		t.Error("feature_version must be a positive, explicit version, not the zero value")
	}
}

func TestValidate_TransactionRefShape(t *testing.T) {
	base := RawData{ID: "1", Name: "Test", Account: "ACC", Amount: 100, Timestamp: "2026-01-15T14:07:33Z"}

	tests := []struct {
		name    string
		ref     string
		wantErr bool
	}{
		{"absent is allowed", "", false},
		{"whitespace-only treated as absent", "   ", false},
		{"valid opaque ref", "core-banking-ref-88421", false},
		{"valid uuid-shaped ref", "3fa85f64-5717-4562-b3fc-2c963f66afa6", false},
		{"valid with underscore", "TXN_2026_08421", false},
		{"over-long ref rejected", strings.Repeat("a", 65), true},
		{"max-length ref allowed", strings.Repeat("a", 64), false},
		{"ref with internal spaces rejected", "core banking ref", true},
		{"ref with punctuation rejected", "ref#88421!", true},
		{"ref with a dot rejected", "txn.88421", true},
		{"name-like ref rejected", "Ngozi Adeyemi", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := base
			r.TransactionRef = tt.ref
			err := r.Validate()
			if tt.wantErr && err == nil {
				t.Errorf("transaction_ref %q: expected validation error, got nil", tt.ref)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("transaction_ref %q: unexpected validation error: %v", tt.ref, err)
			}
			if tt.wantErr {
				ve, ok := err.(*ValidationError)
				if !ok {
					t.Fatalf("transaction_ref %q: expected *ValidationError, got %T", tt.ref, err)
				}
				if ve.Field != "transaction_ref" {
					t.Errorf("transaction_ref %q: expected error field %q, got %q", tt.ref, "transaction_ref", ve.Field)
				}
			}
		})
	}
}

func TestValidate_SignalTypeCaseInsensitiveNormalization(t *testing.T) {
	base := RawData{ID: "1", Name: "Test", Account: "ACC", Amount: 100, Timestamp: "2026-01-15T14:07:33Z"}

	tests := []struct {
		input string
		want  string
	}{
		{"transaction", "transaction"},
		{"Transaction", "transaction"},
		{"TRANSACTION", "transaction"},
		{"LoGiN", "login"},
		{"TRANSFER", "transfer"},
		{"Authentication", "authentication"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			r := base
			r.SignalType = tt.input
			if err := r.Validate(); err != nil {
				t.Fatalf("signal_type %q: unexpected validation error: %v", tt.input, err)
			}
			if r.SignalType != tt.want {
				t.Errorf("signal_type %q: expected Validate to normalize to %q, got %q", tt.input, tt.want, r.SignalType)
			}
		})
	}
}

func TestValidate_EndpointTypeCaseInsensitiveNormalization(t *testing.T) {
	base := RawData{ID: "1", Name: "Test", Account: "ACC", Amount: 100, Timestamp: "2026-01-15T14:07:33Z"}

	tests := []struct {
		input string
		want  string
	}{
		{"MOBILE_APP", "MOBILE_APP"},
		{"mobile_app", "MOBILE_APP"},
		{"Mobile_App", "MOBILE_APP"},
		{"ussd", "USSD"},
		{"USSD", "USSD"},
		{"ivr", "IVR"},
		{"Ivr", "IVR"},
		{"atm", "ATM"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			r := base
			r.EndpointType = tt.input
			if err := r.Validate(); err != nil {
				t.Fatalf("endpoint_type %q: unexpected validation error: %v", tt.input, err)
			}
			if r.EndpointType != tt.want {
				t.Errorf("endpoint_type %q: expected Validate to normalize to %q, got %q", tt.input, tt.want, r.EndpointType)
			}
		})
	}
}

func TestAnonymizeSignal_EmitsCanonicalSignalAndEndpointType(t *testing.T) {
	// End-to-end: Validate (as adapters.ProcessInboundRequest calls it) then
	// AnonymizeSignal must emit the canonical spelling regardless of how the
	// caller cased signal_type/endpoint_type, so the vendor always sees one
	// consistent spelling.
	raw := RawData{ID: "1", Name: "Test", Account: "ACC", Amount: 100, Timestamp: "2026-01-01T00:00:00Z",
		SignalType: "TrAnSaCtIoN", EndpointType: "ussd"}

	if err := raw.Validate(); err != nil {
		t.Fatalf("unexpected validation error: %v", err)
	}

	sig := AnonymizeSignal(raw, "BNK", "salt", "pepper", KeyingBank, 10000, "fallback-id")
	if sig.SignalType != "transaction" {
		t.Errorf("expected canonical signal_type %q, got %q", "transaction", sig.SignalType)
	}
	if sig.Metadata["endpoint_type"] != "USSD" {
		t.Errorf("expected canonical endpoint_type %q, got %v", "USSD", sig.Metadata["endpoint_type"])
	}
}
