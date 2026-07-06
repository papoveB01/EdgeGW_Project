package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
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
	// Container healthcheck mode: the distroless image has no shell/wget,
	// so the binary probes itself (docker-compose runs `/edge-gateway -healthcheck`).
	if len(os.Args) > 1 && os.Args[1] == "-healthcheck" {
		os.Exit(healthcheck())
	}

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
		slog.Error("Required HMAC_SECRET is not set - every Hub forward would fail")
		os.Exit(1)
	}
	if cfg.Local.BankSalt == "" {
		slog.Error("Required local.bank_salt is not set (set BANK_SALT or provide config file)")
		os.Exit(1)
	}
	if os.Getenv("REGIONAL_PEPPER") == "" {
		slog.Warn("REGIONAL_PEPPER not set - cross-bank matching will not work; use Hub-provided value for production")
	}

	inboundKey := os.Getenv("INBOUND_API_KEY")
	if inboundKey == "" {
		slog.Warn("INBOUND_API_KEY not set - /process accepts unauthenticated requests; set it in production")
	}

	slog.Info("Starting Edge Gateway",
		"port", port,
		"institution_id", cfg.Hub.InstitutionID,
		"hub_url", cfg.Hub.HubEndpointURL,
	)

	mux := http.NewServeMux()

	mux.HandleFunc("/health", adapters.HealthCheckHandler)
	mux.HandleFunc("/metrics", adapters.MetricsHandler)
	mux.Handle("/process", middleware.RequireAPIKey(http.HandlerFunc(processTransaction), inboundKey))

	// Wrap with request logging and body size limit middleware
	handler := middleware.RequestLogger(middleware.MaxBodySize(mux, 1<<20)) // 1MB limit

	server := &http.Server{
		Addr:         ":" + port,
		Handler:      handler,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Graceful shutdown: stop accepting connections, let in-flight requests finish.
	shutdownDone := make(chan struct{})
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		sig := <-sigCh
		slog.Info("Shutting down", "signal", sig.String())
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			slog.Warn("Graceful shutdown incomplete", "error", err)
		}
		close(shutdownDone)
	}()

	certFile := os.Getenv("TLS_CERT_FILE")
	keyFile := os.Getenv("TLS_KEY_FILE")

	var err error
	if certFile != "" && keyFile != "" {
		slog.Info("Server listening with TLS", "addr", ":"+port)
		err = server.ListenAndServeTLS(certFile, keyFile)
	} else {
		slog.Warn("TLS_CERT_FILE/TLS_KEY_FILE not set - serving plain HTTP; raw PII will transit unencrypted")
		slog.Info("Server listening", "addr", ":"+port)
		err = server.ListenAndServe()
	}
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		slog.Error("Server failed", "error", err)
		os.Exit(1)
	}
	<-shutdownDone
	slog.Info("Server stopped")
}

// healthcheck probes the local /health endpoint and returns a process exit code.
func healthcheck() int {
	port := os.Getenv("GATEWAY_PORT")
	if port == "" {
		port = "8080"
	}
	scheme := "http"
	client := &http.Client{Timeout: 5 * time.Second}
	if os.Getenv("TLS_CERT_FILE") != "" && os.Getenv("TLS_KEY_FILE") != "" {
		scheme = "https"
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // self-probe on localhost
		}
	}
	resp, err := client.Get(scheme + "://localhost:" + port + "/health")
	if err != nil {
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 1
	}
	return 0
}

func processTransaction(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse and validate incoming request
	rawData, err := adapters.ProcessInboundRequest(r)
	if err != nil {
		slog.Error("Invalid request", "error", err)
		http.Error(w, "Invalid request: "+err.Error(), http.StatusBadRequest)
		return
	}

	cfg := config.Get()
	salt := cfg.Local.BankSalt
	pepper := os.Getenv("REGIONAL_PEPPER")

	anonymized := processor.AnonymizeSignal(*rawData, cfg.Hub.InstitutionID, salt, pepper, cfg.Local.ReportingThreshold)

	// Forward to Hub with retry
	if err := adapters.ForwardToHubWithRetry(r.Context(), anonymized, 2); err != nil {
		slog.Error("Failed to forward to hub",
			"error", err,
			"institution_id", anonymized.InstitutionID,
			"mosaic_prefix", anonymized.IdentityMosaic[:16],
		)
		adapters.RecordMetric("forward_failures", 1)
		http.Error(w, "Failed to forward signal to hub: "+err.Error(), http.StatusBadGateway)
		return
	}

	processingTime := time.Since(startTime)
	adapters.RecordMetric("signals_processed", 1)
	adapters.RecordMetric("processing_time_ms_total", processingTime.Milliseconds())

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
