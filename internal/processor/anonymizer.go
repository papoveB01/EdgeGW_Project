package processor

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"regexp"
	"strings"
	"time"
	"unicode"
)

// MosaicVersion identifies the mosaic derivation scheme so downstream
// consumers can distinguish signals produced by different gateway
// generations.
const MosaicVersion = 2

// FeatureVersion identifies the shape of the derived, model-facing features
// below — amount tier boundaries, the timestamp bucket width, and geohash
// precision. A vendor's pre-trained inference model is fit to this exact
// feature shape (it does not retrain on gateway traffic), so ANY change to
// TierBoundary1/2/3, BucketWidth, or GeohashPrecision is a breaking change
// to that contract and MUST be accompanied by bumping FeatureVersion so the
// vendor can detect the shift.
const FeatureVersion = 1

// Feature-shape contract, versioned by FeatureVersion above. These are the
// only place the amount-tier boundaries, timestamp bucket width, and
// geohash precision are defined — keep them named constants, not literals,
// so the versioned contract stays obvious at a glance.
const (
	// TierBoundary1/2/3 are the upper bounds (inclusive) of TIER_1/2/3 in
	// MapToTier; anything above TierBoundary3 is TIER_4.
	TierBoundary1 = 500
	TierBoundary2 = 2500
	TierBoundary3 = 10000

	// BucketWidth is the window BucketTimestamp truncates timestamps to.
	BucketWidth = 15 * time.Minute

	// GeohashPrecision is the geohash character length used for
	// location_zone; precision 5 gives ~4.9km x 4.9km grid cells.
	GeohashPrecision = 5
)

// Mosaic scopes: global mosaics are keyed only with the shared regional pepper
// over a canonical identifier (BVN/NIN), so the same person produces the same
// mosaic at every member bank. Local mosaics include the bank salt and
// bank-internal identifiers — they are stable within one institution only.
const (
	ScopeGlobal = "global"
	ScopeLocal  = "local"
)

// ValidSignalTypes is the closed allowlist enforced by RawData.Validate for
// SignalType. It exists so the pipeline stays scoped to fraud-relevant
// events rather than silently widening into general behavioural egress to
// a commercial vendor. Package-level so it's easy to extend deliberately.
// Keys are the canonical (lowercase) spelling: RawData.Validate matches
// case-insensitively and rewrites SignalType to the matching key here, so
// every signal reaching the vendor uses one consistent spelling regardless
// of how the caller cased it.
var ValidSignalTypes = map[string]bool{
	"transaction":    true,
	"login":          true,
	"transfer":       true,
	"authentication": true,
}

// ValidEndpointTypes is the closed allowlist enforced by RawData.Validate
// for EndpointType. Package-level so it's easy to extend deliberately.
// Keys are the canonical (uppercase) spelling — see ValidSignalTypes for
// the matching/normalization behavior, mirrored here in uppercase.
//
// USSD and IVR are included alongside the original MOBILE_APP/ATM/POS/WEB/
// BRANCH/API set: this repo targets the Nigerian market (BVN/NIN
// identifiers, Lagos coordinates in examples), where USSD banking is a
// major channel and IVR/call-centre transactions are common — hard-
// rejecting them would drop real traffic. Flagged as a judgment call made
// alongside the hard-reject decision, not something the repo already used
// elsewhere.
var ValidEndpointTypes = map[string]bool{
	"MOBILE_APP": true,
	"ATM":        true,
	"POS":        true,
	"WEB":        true,
	"BRANCH":     true,
	"API":        true,
	"USSD":       true,
	"IVR":        true,
}

// transactionRefPattern is input hygiene for TransactionRef, enforced by
// RawData.Validate. It is deliberately NOT the PII boundary: a charset
// check alone cannot tell an opaque reference from a bare BVN/NIN, a NUBAN
// account number, a phone number, or a name with separators stripped
// ("NgoziAdeyemi") — all of those match this pattern cleanly. The actual
// boundary is that TransactionRef is never forwarded as-is; AnonymizeSignal
// always derives SignalID from it via HMACHash(bankSalt, ...) rather than
// echoing it, so even a caller that populates this field with real PII
// never ships that PII to the vendor. This pattern just rejects obviously
// malformed input (empty after trim is handled separately, wildly long
// values, embedded whitespace/punctuation) before it reaches that HMAC.
var transactionRefPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// RawData represents incoming transaction data with PII and optional fraud-detection fields.
// Latitude/Longitude are optional (card-not-present and online transactions often
// have no meaningful coordinates); absent location maps to ZONE_UNKNOWN.
type RawData struct {
	ID                     string   `json:"id"`
	Name                   string   `json:"name"`
	NationalID             string   `json:"national_id,omitempty"`
	Account                string   `json:"account"`
	Amount                 float64  `json:"amount"`
	Latitude               *float64 `json:"latitude,omitempty"`
	Longitude              *float64 `json:"longitude,omitempty"`
	Timestamp              string   `json:"timestamp"`
	DeviceID               string   `json:"device_id,omitempty"`
	DeviceIDHash           string   `json:"device_id_hash,omitempty"`
	IP                     string   `json:"ip,omitempty"`
	IPHash                 string   `json:"ip_hash,omitempty"`
	BranchID               string   `json:"branch_id,omitempty"`
	SignalType             string   `json:"signal_type,omitempty"`
	EndpointType           string   `json:"endpoint_type,omitempty"`
	CounterpartyID         string   `json:"counterparty_id,omitempty"`
	CounterpartyNationalID string   `json:"counterparty_national_id,omitempty"`
	// TransactionRef is an optional caller-supplied reference used to derive
	// the outgoing signal_id (the join key for out-of-band vendor results).
	// It is never forwarded to the vendor as-is: AnonymizeSignal always
	// derives signal_id from it with HMACHash(bankSalt, ...), so even if a
	// caller puts a real identifier here (deliberately or by mistake) it
	// never reaches the vendor in recoverable form. When absent, the
	// gateway generates a random signal_id instead.
	TransactionRef string `json:"transaction_ref,omitempty"`
}

// Validate checks required fields hold usable values, not just that keys exist.
func (r *RawData) Validate() error {
	if strings.TrimSpace(r.ID) == "" {
		return &ValidationError{Field: "id", Message: "must be a non-empty string"}
	}
	if strings.TrimSpace(r.Name) == "" {
		return &ValidationError{Field: "name", Message: "must be a non-empty string"}
	}
	if strings.TrimSpace(r.Account) == "" {
		return &ValidationError{Field: "account", Message: "must be a non-empty string"}
	}
	if r.Amount <= 0 || math.IsInf(r.Amount, 0) {
		return &ValidationError{Field: "amount", Message: "must be a positive number"}
	}
	if _, err := time.Parse(time.RFC3339Nano, r.Timestamp); err != nil {
		return &ValidationError{Field: "timestamp", Message: "must be RFC 3339 (e.g. 2026-01-15T14:07:33Z)"}
	}
	if (r.Latitude == nil) != (r.Longitude == nil) {
		return &ValidationError{Field: "latitude/longitude", Message: "must be provided together or omitted together"}
	}
	if r.Latitude != nil {
		if *r.Latitude < -90 || *r.Latitude > 90 || math.IsNaN(*r.Latitude) {
			return &ValidationError{Field: "latitude", Message: "must be between -90 and 90"}
		}
		if *r.Longitude < -180 || *r.Longitude > 180 || math.IsNaN(*r.Longitude) {
			return &ValidationError{Field: "longitude", Message: "must be between -180 and 180"}
		}
	}
	// Whitespace-only transaction_ref is treated the same as absent (it's
	// what AnonymizeSignal falls back on for signal_id generation too); a
	// non-blank value must be an opaque token, never free text that could
	// carry PII.
	if ref := strings.TrimSpace(r.TransactionRef); ref != "" && !transactionRefPattern.MatchString(ref) {
		return &ValidationError{Field: "transaction_ref", Message: "must be an opaque reference matching ^[A-Za-z0-9_-]{1,64}$ (no spaces or punctuation; must not contain names or identifiers)"}
	}
	// Empty signal_type is allowed here — it defaults to "transaction" in
	// AnonymizeSignal. A non-empty value must be on the allowlist, matched
	// case-insensitively; on success r.SignalType is rewritten to the
	// allowlist's canonical (lowercase) spelling so every signal reaching
	// the vendor is consistent regardless of caller casing.
	if r.SignalType != "" {
		canonical := strings.ToLower(r.SignalType)
		if !ValidSignalTypes[canonical] {
			return &ValidationError{Field: "signal_type", Message: fmt.Sprintf("unknown signal_type %q", r.SignalType)}
		}
		r.SignalType = canonical
	}
	// Same case-insensitive match + canonical (uppercase) rewrite for
	// endpoint_type.
	if r.EndpointType != "" {
		canonical := strings.ToUpper(r.EndpointType)
		if !ValidEndpointTypes[canonical] {
			return &ValidationError{Field: "endpoint_type", Message: fmt.Sprintf("unknown endpoint_type %q", r.EndpointType)}
		}
		r.EndpointType = canonical
	}
	return nil
}

// ValidationError represents a field validation failure.
type ValidationError struct {
	Field   string
	Message string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("validation error: %s - %s", e.Field, e.Message)
}

// AnonymizedSignal represents the anonymized output — no PII.
type AnonymizedSignal struct {
	// SignalID uniquely identifies this event (not the person — see
	// IdentityMosaic for that). It is the join key the bank uses to match
	// out-of-band vendor results back to this signal. When RawData.
	// TransactionRef is supplied, SignalID is HMACHash(bankSalt, "v2|sigid|"
	// + strings.TrimSpace(ref)) over the EXACT trimmed bytes of the
	// reference — deliberately NOT NormalizeID, which uppercases and strips
	// '-'/'.'  NormalizeID exists to converge inconsistently-formatted
	// national IDs onto one value; a caller-supplied transaction reference
	// needs the opposite property; two distinct references must never
	// collide, so "TX-001", "TX.001", "tx001" and "TX001" are all treated
	// as different references and derive different SignalIDs.
	// TransactionRef is case-sensitive and punctuation-sensitive as a
	// result. This stays deterministic (same ref -> same SignalID, so it
	// still works as an idempotency key) but never exposes the raw ref
	// itself, so a caller that puts a real identifier in TransactionRef
	// never ships it to the vendor. The bank recomputes the same HMAC over
	// its own references to join results back; the vendor, without
	// BANK_SALT, cannot invert it. When TransactionRef is absent, SignalID
	// is a random UUIDv4 instead.
	SignalID       string `json:"signal_id"`
	InstitutionID  string `json:"institution_id"`
	SignalType     string `json:"signal_type"`
	IdentityMosaic string `json:"identity_mosaic"`
	MosaicScope    string `json:"mosaic_scope"`
	MosaicVersion  int    `json:"mosaic_version"`
	// FeatureVersion identifies the shape of the derived features in
	// Metadata (amount tier, timestamp bucket, geohash precision) — see the
	// FeatureVersion constant doc for what bumps it.
	FeatureVersion         int                    `json:"feature_version"`
	Timestamp              string                 `json:"timestamp"`
	Metadata               map[string]interface{} `json:"metadata"`
	DestinationMosaic      string                 `json:"destination_mosaic,omitempty"`
	DestinationMosaicScope string                 `json:"destination_mosaic_scope,omitempty"`
}

// Hash creates a SHA-256 hash of the input string.
func Hash(input string) string {
	hash := sha256.Sum256([]byte(input))
	return hex.EncodeToString(hash[:])
}

// HMACHash computes hex-encoded HMAC-SHA256(key, message). Mosaics use a keyed
// MAC rather than plain concatenation-hashing so an attacker without the key
// cannot mount an offline dictionary attack on low-entropy identifiers.
func HMACHash(key, message string) string {
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(message))
	return hex.EncodeToString(mac.Sum(nil))
}

// NormalizeID strips whitespace, dots and dashes and uppercases, so
// "2234-5678 901" and "22345678901" produce the same mosaic.
func NormalizeID(s string) string {
	var b strings.Builder
	for _, r := range s {
		if unicode.IsSpace(r) || r == '-' || r == '.' {
			continue
		}
		b.WriteRune(unicode.ToUpper(r))
	}
	return b.String()
}

// NormalizeName uppercases and collapses whitespace so casing/spacing
// differences don't split one person into multiple local mosaics.
func NormalizeName(s string) string {
	return strings.Join(strings.Fields(strings.ToUpper(s)), " ")
}

// MapToTier converts exact amount to privacy-preserving tier. Boundaries are
// the versioned feature contract — see TierBoundary1/2/3 and FeatureVersion.
func MapToTier(amount float64) string {
	switch {
	case amount <= TierBoundary1:
		return "TIER_1"
	case amount <= TierBoundary2:
		return "TIER_2"
	case amount <= TierBoundary3:
		return "TIER_3"
	default:
		return "TIER_4"
	}
}

// base32 charset for geohash encoding
const base32 = "0123456789bcdefghjkmnpqrstuvwxyz"

// Geohash encodes lat/lon to a geohash string of the given precision.
// AnonymizeSignal calls this with GeohashPrecision (part of the versioned
// feature contract — see FeatureVersion). Precision 5 gives ~4.9km x 4.9km
// grid cells — good for privacy-preserving location zones.
// Out-of-range or NaN coordinates return ZONE_UNKNOWN.
func Geohash(lat, lon float64, precision int) string {
	if math.IsNaN(lat) || math.IsNaN(lon) || precision <= 0 ||
		lat < -90 || lat > 90 || lon < -180 || lon > 180 {
		return "ZONE_UNKNOWN"
	}

	minLat, maxLat := -90.0, 90.0
	minLon, maxLon := -180.0, 180.0

	var hash strings.Builder
	isEven := true
	bit := 0
	ch := 0

	for hash.Len() < precision {
		if isEven {
			mid := (minLon + maxLon) / 2
			if lon >= mid {
				ch |= 1 << (4 - bit)
				minLon = mid
			} else {
				maxLon = mid
			}
		} else {
			mid := (minLat + maxLat) / 2
			if lat >= mid {
				ch |= 1 << (4 - bit)
				minLat = mid
			} else {
				maxLat = mid
			}
		}

		isEven = !isEven
		bit++
		if bit == 5 {
			hash.WriteByte(base32[ch])
			bit = 0
			ch = 0
		}
	}

	return hash.String()
}

// BucketTimestamp rounds an RFC 3339 timestamp down to a BucketWidth-wide
// UTC bucket (part of the versioned feature contract — see FeatureVersion).
// Timezone offsets are normalized to UTC so signals from different
// institutions are comparable downstream. Unparseable input returns
// TIME_UNKNOWN — the raw value is never passed through.
func BucketTimestamp(ts string) string {
	t, err := time.Parse(time.RFC3339Nano, ts)
	if err != nil {
		return "TIME_UNKNOWN"
	}
	return t.UTC().Truncate(BucketWidth).Format(time.RFC3339)
}

// NewSignalID generates a random per-event identifier in UUIDv4 form using
// crypto/rand. It carries no information about the underlying transaction
// or person — it is pure randomness, never derived from PII.
//
// On rand.Read failure this panics rather than returning an error. That is
// a deliberate, scoped tradeoff, not an oversight:
//   - rand.Read only fails when the OS's CSPRNG itself is broken (see the
//     crypto/rand docs) — a condition under which continuing to serve any
//     request is already unsound, not just this one field.
//   - Threading a real error out of here would change AnonymizeSignal's
//     signature (today a pure `(RawData, ...) AnonymizedSignal` function,
//     by design per this repo's architecture notes) and every caller,
//     including cmd/gateway/main.go's processTransaction — which is
//     explicitly out of scope for this change beyond echoing signal_id in
//     the response body.
//
// Known gap this leaves: net/http recovers panics per-connection with no
// structured log or metric, so unlike every other failure path in
// processTransaction (slog.Error + a proper http.Error status), a
// rand.Read failure currently surfaces to the caller as a bare connection
// reset. If this entropy-failure mode matters for this deployment's threat
// model, the fix is to make AnonymizeSignal return an error and update
// processTransaction (and its tests) to log and respond 500 — tracked as
// follow-up work rather than folded into this change; see
// https://github.com/papoveB01/EdgeGW_Project/issues/4.
func NewSignalID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("processor: failed to read random bytes for signal_id: " + err.Error())
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10xx
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// AnonymizeSignal processes raw PII data into an anonymized signal.
// Uses delimited field concatenation to prevent boundary collisions.
func AnonymizeSignal(rawPii RawData, institutionID string, salt string, pepper string, reportingThreshold float64) AnonymizedSignal {
	// 1. Identity Mosaic (v2).
	// With a canonical national ID (BVN/NIN): HMAC keyed by the shared pepper
	// only, so every member bank derives the same mosaic for the same person.
	// Without one: HMAC keyed by salt+pepper over normalized local identity —
	// stable within this institution only, tagged ScopeLocal so the Hub
	// doesn't attempt cross-bank matching on it.
	var mosaic, mosaicScope string
	if nid := NormalizeID(rawPii.NationalID); nid != "" {
		mosaic = HMACHash(pepper, "v2|id|"+nid)
		mosaicScope = ScopeGlobal
	} else {
		mosaic = HMACHash(salt+"|"+pepper, "v2|local|"+NormalizeID(rawPii.ID)+"|"+NormalizeName(rawPii.Name))
		mosaicScope = ScopeLocal
	}

	// 2. Amount tier
	tier := MapToTier(rawPii.Amount)

	// 3. Near-threshold flag for Multi-Bank Structuring detection
	isNearThreshold := reportingThreshold > 0 && rawPii.Amount >= reportingThreshold*0.95

	// 4. Real geohash for spatial grouping (GeohashPrecision = ~4.9km cells)
	zone := "ZONE_UNKNOWN"
	if rawPii.Latitude != nil && rawPii.Longitude != nil {
		zone = Geohash(*rawPii.Latitude, *rawPii.Longitude, GeohashPrecision)
	}

	// 5. Timestamp bucketing (15-minute windows, normalized to UTC)
	bucketedTimestamp := BucketTimestamp(rawPii.Timestamp)

	if institutionID == "" {
		institutionID = "BNK_DEFAULT"
	}
	signalType := rawPii.SignalType
	if signalType == "" {
		signalType = "transaction"
	}

	// 6. Per-event correlation ID. IdentityMosaic is per-person and stable
	// across every transaction, so nothing else in this payload can join a
	// single event back to a caller-supplied transaction.
	//
	// When the caller supplies a reference, derive signal_id from it rather
	// than echoing it: TransactionRef's format check (transactionRefPattern
	// in Validate) only screens obviously malformed input — a bare BVN/NIN,
	// a NUBAN account number, a phone number, or a name with separators
	// stripped all pass it cleanly. HMAC-keying with the bank's own salt
	// keeps the identifier the bank can recompute (same ref -> same
	// signal_id, so it still works as an idempotency key), while ensuring
	// nothing recoverable ever reaches the vendor, who never holds
	// BANK_SALT. When absent, generate a random one instead — still never
	// derived from PII.
	//
	// Deliberately NOT NormalizeID here: NormalizeID uppercases and strips
	// '-'/'.' so differently-formatted national IDs converge onto one
	// mosaic — exactly the wrong property for an opaque caller reference,
	// where "TX-001", "TX.001", "tx001" and "TX001" must be treated as
	// distinct references (they could be four different transactions) and
	// must not collide onto the same signal_id. Hash the trimmed raw bytes
	// instead — TransactionRef is case-sensitive and punctuation-sensitive.
	var signalID string
	if ref := strings.TrimSpace(rawPii.TransactionRef); ref != "" {
		signalID = HMACHash(salt, "v2|sigid|"+ref)
	} else {
		signalID = NewSignalID()
	}

	meta := map[string]interface{}{
		"amount_tier":   tier,
		"location_zone": zone,
		"account_hash":  Hash(rawPii.Account + "|" + salt),
	}
	if isNearThreshold {
		meta["is_near_threshold"] = true
	}

	// Device fingerprint hash
	if rawPii.DeviceIDHash != "" {
		meta["device_id_hash"] = rawPii.DeviceIDHash
	} else if rawPii.DeviceID != "" {
		meta["device_id_hash"] = Hash(rawPii.DeviceID + "|" + salt)
	}

	// IP hash
	if rawPii.IPHash != "" {
		meta["ip_hash"] = rawPii.IPHash
	} else if rawPii.IP != "" {
		meta["ip_hash"] = Hash(rawPii.IP + "|" + salt)
	}

	// Branch ID (not PII — physical location identifier)
	if rawPii.BranchID != "" {
		meta["branch_id"] = rawPii.BranchID
	}
	if rawPii.EndpointType != "" {
		meta["endpoint_type"] = rawPii.EndpointType
	}

	out := AnonymizedSignal{
		SignalID:       signalID,
		InstitutionID:  institutionID,
		SignalType:     signalType,
		IdentityMosaic: mosaic,
		MosaicScope:    mosaicScope,
		MosaicVersion:  MosaicVersion,
		FeatureVersion: FeatureVersion,
		Timestamp:      bucketedTimestamp,
		Metadata:       meta,
	}

	// Destination mosaic for Mule Route detection. The global derivation is
	// identical to the identity mosaic's, so a counterparty's destination
	// mosaic matches their own identity mosaic when they transact — exactly
	// what route-following needs.
	if cn := NormalizeID(rawPii.CounterpartyNationalID); cn != "" {
		out.DestinationMosaic = HMACHash(pepper, "v2|id|"+cn)
		out.DestinationMosaicScope = ScopeGlobal
	} else if rawPii.CounterpartyID != "" {
		out.DestinationMosaic = HMACHash(salt+"|"+pepper, "v2|local|"+NormalizeID(rawPii.CounterpartyID))
		out.DestinationMosaicScope = ScopeLocal
	}

	return out
}
