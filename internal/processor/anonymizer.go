package processor

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"strings"
)

// RawData represents incoming transaction data with PII and optional fraud-detection fields.
type RawData struct {
	ID             string  `json:"id"`
	Name           string  `json:"name"`
	Account        string  `json:"account"`
	Amount         float64 `json:"amount"`
	Latitude       float64 `json:"latitude"`
	Longitude      float64 `json:"longitude"`
	Timestamp      string  `json:"timestamp"`
	DeviceID       string  `json:"device_id,omitempty"`
	DeviceIDHash   string  `json:"device_id_hash,omitempty"`
	IP             string  `json:"ip,omitempty"`
	IPHash         string  `json:"ip_hash,omitempty"`
	BranchID       string  `json:"branch_id,omitempty"`
	SignalType     string  `json:"signal_type,omitempty"`
	EndpointType   string  `json:"endpoint_type,omitempty"`
	CounterpartyID string  `json:"counterparty_id,omitempty"`
}

// AnonymizedSignal represents the anonymized output — no PII.
type AnonymizedSignal struct {
	InstitutionID     string                 `json:"institution_id"`
	SignalType        string                 `json:"signal_type"`
	IdentityMosaic    string                 `json:"identity_mosaic"`
	Timestamp         string                 `json:"timestamp"`
	Metadata          map[string]interface{} `json:"metadata"`
	DestinationMosaic string                 `json:"destination_mosaic,omitempty"`
}

// Hash creates a SHA-256 hash of the input string.
func Hash(input string) string {
	hash := sha256.Sum256([]byte(input))
	return hex.EncodeToString(hash[:])
}

// MapToTier converts exact amount to privacy-preserving tier.
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

// base32 charset for geohash encoding
const base32 = "0123456789bcdefghjkmnpqrstuvwxyz"

// Geohash encodes lat/lon to a geohash string of the given precision.
// Precision 5 gives ~4.9km x 4.9km grid cells — good for privacy-preserving location zones.
func Geohash(lat, lon float64, precision int) string {
	if math.IsNaN(lat) || math.IsNaN(lon) || precision <= 0 {
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

// BucketTimestamp rounds a timestamp to 15-minute buckets for privacy.
// Input: ISO 8601 timestamp string. Returns bucketed string or original if parsing fails.
func BucketTimestamp(ts string) string {
	// Simple approach: truncate minutes to 15-min boundaries, zero seconds
	// Works with format "2006-01-02T15:04:05..."
	if len(ts) < 16 {
		return ts
	}
	// Parse minute
	minStr := ts[14:16]
	min := 0
	for _, c := range minStr {
		min = min*10 + int(c-'0')
	}
	bucketed := min - (min % 15)
	return fmt.Sprintf("%s%02d:00", ts[:14], bucketed)
}

// AnonymizeSignal processes raw PII data into an anonymized signal.
// Uses delimited field concatenation to prevent boundary collisions.
func AnonymizeSignal(rawPii RawData, institutionID string, salt string, pepper string, reportingThreshold float64) AnonymizedSignal {
	// 1. Identity Mosaic: SHA-256 with delimiters to prevent field boundary collisions
	mosaicInput := rawPii.ID + "|" + rawPii.Name + "|" + salt + "|" + pepper
	mosaic := Hash(mosaicInput)

	// 2. Amount tier
	tier := MapToTier(rawPii.Amount)

	// 3. Near-threshold flag for Multi-Bank Structuring detection
	isNearThreshold := reportingThreshold > 0 && rawPii.Amount >= reportingThreshold*0.95

	// 4. Real geohash for spatial grouping (precision 5 = ~4.9km cells)
	zone := Geohash(rawPii.Latitude, rawPii.Longitude, 5)

	// 5. Timestamp bucketing (15-minute windows)
	bucketedTimestamp := BucketTimestamp(rawPii.Timestamp)

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
		InstitutionID:  institutionID,
		SignalType:     signalType,
		IdentityMosaic: mosaic,
		Timestamp:      bucketedTimestamp,
		Metadata:       meta,
	}

	// Destination mosaic for Mule Route detection
	if rawPii.CounterpartyID != "" {
		out.DestinationMosaic = Hash(rawPii.CounterpartyID + "|" + salt + "|" + pepper)
	}

	return out
}
