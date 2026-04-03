package processor

import (
	"crypto/sha256"
	"encoding/hex"
	"math"
)

// RawData represents incoming transaction data with PII and optional fraud-detection fields.
// Optional fields (device_id, ip, branch_id) enable Hub fraud detection: Midnight Sweep, Credential Stuffing, Impossible Travel.
type RawData struct {
	ID        string  `json:"id"`
	Name      string  `json:"name"`
	Account   string  `json:"account"`
	Amount    float64 `json:"amount"`
	Latitude  float64 `json:"latitude"`
	Longitude float64 `json:"longitude"`
	Timestamp string  `json:"timestamp"`
	// Optional: for Credential Stuffing (cross-bank) and Midnight Sweep. Bank can send device_id (gateway hashes) or device_id_hash (pre-hashed).
	DeviceID     string `json:"device_id,omitempty"`
	DeviceIDHash string `json:"device_id_hash,omitempty"`
	// Optional: for Midnight Sweep anchor. Bank can send ip (gateway hashes) or ip_hash (pre-hashed).
	IP     string `json:"ip,omitempty"`
	IPHash string `json:"ip_hash,omitempty"`
	// Optional: for Impossible Travel. Physical ATM/branch identifier (e.g. LAG-01, ABV-04). Must match branch_locations in Hub.
	BranchID string `json:"branch_id,omitempty"`
	// Optional: signal_type (default "transaction"), endpoint_type (e.g. BRANCH, ATM, MOBILE).
	SignalType   string `json:"signal_type,omitempty"`
	EndpointType string `json:"endpoint_type,omitempty"`
	// Optional: for transfers – counterparty/destination identity. Gateway hashes to destination_mosaic for Mule Route detection.
	CounterpartyID string `json:"counterparty_id,omitempty"`
}

// AnonymizedSignal represents the anonymized output
type AnonymizedSignal struct {
	InstitutionID     string                 `json:"institution_id"`
	SignalType        string                 `json:"signal_type"`
	IdentityMosaic    string                 `json:"identity_mosaic"`
	Timestamp         string                 `json:"timestamp"`
	Metadata          map[string]interface{} `json:"metadata"`
	DestinationMosaic string                 `json:"destination_mosaic,omitempty"` // For transfers: hashed counterparty (Mule Route)
}

// Hash creates a SHA-256 hash of the input string
func Hash(input string) string {
	hash := sha256.Sum256([]byte(input))
	return hex.EncodeToString(hash[:])
}

// TruncateMosaic safely returns the first n characters of a string.
func TruncateMosaic(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// MapToTier converts exact amount to privacy-preserving tier
func MapToTier(amount float64) string {
	switch {
	case amount <= 500:
		return "TIER_1"
	case amount <= 2500:
		return "TIER_2"
	case amount <= 10000:
		return "TIER_3"
	default:
		return "TIER_4"
	}
}

// GetGeohash converts lat/lon to a standard base32 geohash string of the given precision.
// Nearby coordinates share a common prefix, preserving spatial proximity for fraud zone detection.
func GetGeohash(lat, lon float64, precision int) string {
	if math.IsNaN(lat) || math.IsNaN(lon) {
		return "unknown"
	}
	if precision <= 0 {
		precision = 5
	}

	const base32 = "0123456789bcdefghjkmnpqrstuvwxyz"

	minLat, maxLat := -90.0, 90.0
	minLon, maxLon := -180.0, 180.0

	var hash []byte
	bit := 0
	ch := 0
	isLon := true // geohash alternates lon/lat bits, starting with lon

	for len(hash) < precision {
		if isLon {
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
		isLon = !isLon
		bit++
		if bit == 5 {
			hash = append(hash, base32[ch])
			ch = 0
			bit = 0
		}
	}

	return string(hash)
}

// AnonymizeSignal processes raw PII data into anonymized signal.
// institutionID should come from gateway config (Hub param from Hub UI).
// reportingThreshold is the AML reporting limit (e.g. 10000); when amount is within 5%, is_near_threshold is set for Multi-Bank Structuring.
func AnonymizeSignal(rawPii RawData, institutionID string, salt string, pepper string, reportingThreshold float64) AnonymizedSignal {
	// 1. Create Identity Mosaic: SHA-256(ID + Name + BANK_SALT + REGIONAL_PEPPER)
	mosaicInput := rawPii.ID + rawPii.Name + salt + pepper
	mosaic := Hash(mosaicInput)

	// 2. Convert Amount to Tier
	tier := MapToTier(rawPii.Amount)

	// 3. High-Risk Sentinel (Multi-Bank Structuring): flag "near threshold" when within 5% of AML limit
	isNearThreshold := reportingThreshold > 0 && rawPii.Amount >= reportingThreshold*0.95

	// 4. Convert Location to Geohash (Zone)
	zone := GetGeohash(rawPii.Latitude, rawPii.Longitude, 5)

	if institutionID == "" {
		institutionID = "BNK_DEFAULT"
	}
	signalType := rawPii.SignalType
	if signalType == "" {
		signalType = "transaction"
	}
	meta := map[string]interface{}{
		"amount_tier":   tier,
		"location_zone": zone,
		"account_hash":  Hash(rawPii.Account + salt),
	}
	if isNearThreshold {
		meta["is_near_threshold"] = true
	}
	// Device fingerprint: required for Credential Stuffing (cross-bank) and Midnight Sweep
	if rawPii.DeviceIDHash != "" {
		meta["device_id_hash"] = rawPii.DeviceIDHash
	} else if rawPii.DeviceID != "" {
		meta["device_id_hash"] = Hash(rawPii.DeviceID + salt)
	}
	// IP hash: optional anchor for Midnight Sweep
	if rawPii.IPHash != "" {
		meta["ip_hash"] = rawPii.IPHash
	} else if rawPii.IP != "" {
		meta["ip_hash"] = Hash(rawPii.IP + salt)
	}
	// Branch ID: required for Impossible Travel (physical ATM/branch location)
	if rawPii.BranchID != "" {
		meta["branch_id"] = rawPii.BranchID
	}
	if rawPii.EndpointType != "" {
		meta["endpoint_type"] = rawPii.EndpointType
	}
	out := AnonymizedSignal{
		InstitutionID:  institutionID,
		SignalType:     signalType,
		IdentityMosaic: mosaic,
		Timestamp:      rawPii.Timestamp,
		Metadata:       meta,
	}
	// Mule Route: hash counterparty to destination_mosaic when present (transfer to another identity)
	if rawPii.CounterpartyID != "" {
		out.DestinationMosaic = Hash(rawPii.CounterpartyID + salt + pepper)
	}
	return out
}
