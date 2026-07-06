package adapters

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/papoveB01/EdgeGW_Project/internal/processor"
)

// ProcessInboundRequest handles incoming transaction data from Core Banking System.
// Decodes directly into RawData and validates field values (not just presence).
func ProcessInboundRequest(r *http.Request) (*processor.RawData, error) {
	defer r.Body.Close()

	var rawData processor.RawData
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(&rawData); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}

	if err := rawData.Validate(); err != nil {
		return nil, err
	}

	return &rawData, nil
}

// HealthCheckHandler returns gateway health status.
func HealthCheckHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"service":   "edge-gateway",
		"version":   "2.0.0",
	})
}
