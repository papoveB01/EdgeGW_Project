package main

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/papoveB01/EdgeGW_Project/internal/adapters"
	"github.com/papoveB01/EdgeGW_Project/internal/config"
	"github.com/papoveB01/EdgeGW_Project/internal/middleware"
	"github.com/papoveB01/EdgeGW_Project/internal/processor"
)

func main() {
	// Structured JSON logger
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	cfg := config.Load()

	port := os.Getenv("GATEWAY_PORT")
	if port == "" {
		port = "8080"
	}

	// Validate required config
	if cfg.Hub.InstitutionID == "" {
		slog.Error("Required hub.institution_id is not set (set INSTITUTION_ID or provide config file)")
		os.Exit(1)
	}
	if cfg.Hub.APIKey == "" {
		slog.Error("Required hub.api_key is not set (set API_KEY or provide config file)")
		os.Exit(1)
	}
	if cfg.Hub.HubEndpointURL == "" {
		slog.Error("Required hub.hub_endpoint_url is not set (set HUB_API_URL or provide config file)")
		os.Exit(1)
	}
	if os.Getenv("HMAC_SECRET") == "" {
		slog.Warn("HMAC_SECRET not set - payload signing will fail unless set via env")
	}
	if cfg.Local.BankSalt == "" {
		slog.Error("Required local.bank_salt is not set (set BANK_SALT or provide config file)")
		os.Exit(1)
	}
	if os.Getenv("REGIONAL_PEPPER") == "" {
		slog.Warn("REGIONAL_PEPPER not set - use Hub-provided value for production")
	}

	slog.Info("Starting Edge Gateway",
		"port", port,
		"institution_id", cfg.Hub.InstitutionID,
		"hub_url", cfg.Hub.HubEndpointURL,
	)

	mux := http.NewServeMux()

	mux.HandleFunc("/health", adapters.HealthCheckHandler)
	mux.HandleFunc("/metrics", adapters.MetricsHandler)
	mux.HandleFunc("/process", processTransaction)
	mux.HandleFunc("/resolve-pii", resolvePII)

	// Wrap with request logging and body size limit middleware
	handler := middleware.RequestLogger(middleware.MaxBodySize(mux, 1<<20)) // 1MB limit

	server := &http.Server{
		Addr:         ":" + port,
		Handler:      handler,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Graceful shutdown
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		sig := <-sigCh
		slog.Info("Shutting down", "signal", sig.String())
		server.Close()
	}()

	slog.Info("Server listening", "addr", ":"+port)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		slog.Error("Server failed", "error", err)
		os.Exit(1)
	}
	slog.Info("Server stopped")
}

func processTransaction(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse incoming request
	rawDataMap, err := adapters.ProcessInboundRequest(r)
	if err != nil {
		slog.Error("Invalid request", "error", err)
		http.Error(w, "Invalid request: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Convert to RawData struct
	rawDataJSON, _ := json.Marshal(rawDataMap)
	var rawData processor.RawData
	if err := json.Unmarshal(rawDataJSON, &rawData); err != nil {
		slog.Error("Invalid data format", "error", err)
		http.Error(w, "Invalid data format", http.StatusBadRequest)
		return
	}

	cfg := config.Get()
	salt := cfg.Local.BankSalt
	pepper := os.Getenv("REGIONAL_PEPPER")

	reportingThreshold := cfg.Local.ReportingThreshold
	if reportingThreshold <= 0 {
		reportingThreshold = 10000
	}
	anonymized := processor.AnonymizeSignal(rawData, cfg.Hub.InstitutionID, salt, pepper, reportingThreshold)

	// Forward to Hub with retry
	if err := adapters.ForwardToHubWithRetry(anonymized, 3); err != nil {
		slog.Error("Failed to forward to hub",
			"error", err,
			"institution_id", anonymized.InstitutionID,
			"mosaic_prefix", anonymized.IdentityMosaic[:16],
		)
		adapters.RecordMetric("forward_failures", 1)
		http.Error(w, "Failed to forward signal to hub: "+err.Error(), http.StatusInternalServerError)
		return
	}

	processingTime := time.Since(startTime)
	adapters.RecordMetric("signals_processed", 1)
	adapters.RecordMetric("processing_time_ms", processingTime.Milliseconds())

	slog.Info("Transaction processed",
		"processing_time", processingTime.String(),
		"mosaic_prefix", anonymized.IdentityMosaic[:16],
		"institution_id", anonymized.InstitutionID,
		"amount_tier", anonymized.Metadata["amount_tier"],
	)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":             "processed",
		"processing_time_ms": processingTime.Milliseconds(),
		"identity_mosaic":    anonymized.IdentityMosaic[:16] + "...",
	})
}

func resolvePII(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Mosaic       string `json:"mosaic"`
		OfficerToken string `json:"officer_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	if body.Mosaic == "" {
		http.Error(w, "mosaic is required", http.StatusBadRequest)
		return
	}
	if body.OfficerToken == "" {
		http.Error(w, "officer_token is required (Hub JWT)", http.StatusUnauthorized)
		return
	}

	// In production: validate officer_token JWT, then lookup mosaic in local DB/store
	// For demo: return mock local PII
	mock := map[string]interface{}{
		"customer_id":   "LOCAL-" + body.Mosaic[len(body.Mosaic)-8:],
		"account_id":    "***4567",
		"name_redacted": "*** (resolved locally)",
		"resolved_at":   time.Now().UTC().Format(time.RFC3339),
		"note":          "Demo: In production this would be real PII from your local audit store.",
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(mock)
}
