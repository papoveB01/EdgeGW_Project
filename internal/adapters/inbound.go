package adapters

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// ProcessInboundRequest handles incoming transaction data from Core Banking System.
func ProcessInboundRequest(r *http.Request) (interface{}, error) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()

	var rawData map[string]interface{}
	if err := json.Unmarshal(body, &rawData); err != nil {
		return nil, err
	}

	requiredFields := []string{"id", "name", "account", "amount", "latitude", "longitude", "timestamp"}
	for _, field := range requiredFields {
		if _, exists := rawData[field]; !exists {
			return nil, &ValidationError{Field: field, Message: "required field missing"}
		}
	}

	return rawData, nil
}

// ValidationError represents a validation error.
type ValidationError struct {
	Field   string
	Message string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("validation error: %s - %s", e.Field, e.Message)
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
