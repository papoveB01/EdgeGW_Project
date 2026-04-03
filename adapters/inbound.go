package adapters

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// maxBodySize is the maximum allowed request body size (1 MB).
const maxBodySize = 1 << 20

// ProcessInboundRequest handles incoming transaction data from Core Banking System
func ProcessInboundRequest(r *http.Request) (interface{}, error) {
	defer r.Body.Close()

	// Read request body with size limit to prevent memory exhaustion
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBodySize+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxBodySize {
		return nil, fmt.Errorf("request body exceeds maximum size of %d bytes", maxBodySize)
	}

	// Parse JSON
	var rawData map[string]interface{}
	if err := json.Unmarshal(body, &rawData); err != nil {
		return nil, err
	}

	// Validate required fields
	requiredFields := []string{"id", "name", "account", "amount", "latitude", "longitude", "timestamp"}
	for _, field := range requiredFields {
		if _, exists := rawData[field]; !exists {
			return nil, &ValidationError{Field: field, Message: "required field missing"}
		}
	}

	return rawData, nil
}

// ValidationError represents a validation error
type ValidationError struct {
	Field   string
	Message string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("validation error: %s - %s", e.Field, e.Message)
}

// HealthCheckHandler returns gateway health status
func HealthCheckHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"service":   "edge-gateway",
	})
}
