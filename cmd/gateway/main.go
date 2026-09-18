package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/papoveB01/EdgeGW_Project/internal/adapters"
	"github.com/papoveB01/EdgeGW_Project/internal/config"
	"github.com/papoveB01/EdgeGW_Project/internal/middleware"
	"github.com/papoveB01/EdgeGW_Project/internal/processor"
	"github.com/papoveB01/EdgeGW_Project/internal/spool"
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

	// Validate required config. Requiredness depends on GATEWAY_MODE: a
	// middleware gateway must fail fast if it has no destination or
	// credentials to reach it; a standalone gateway needs neither, since it
	// runs independent of any external system (see validateStartup).
	if problems := validateStartup(cfg); len(problems) > 0 {
		for _, p := range problems {
			slog.Error(p)
		}
		os.Exit(1)
	}

	inboundKey := os.Getenv("INBOUND_API_KEY")
	if inboundKey == "" {
		slog.Warn("INBOUND_API_KEY not set - /process accepts unauthenticated requests; set it in production")
	}

	// Delivery destination: middleware forwards one-way to the external
	// vendor platform; standalone has no external system, so signals are
	// written to a local durable sink instead. Either way, "forward now"
	// (sync) or "forward later" (spool) always lands somewhere on disk or
	// with the vendor - there is no silent no-op / discard path.
	var sink *localSink
	deliver := spool.ForwardFunc(adapters.ForwardPayload)
	syncForward := func(ctx context.Context, signal processor.AnonymizedSignal) error {
		return adapters.ForwardToHubWithRetry(ctx, signal, 2)
	}
	if cfg.IsStandalone() {
		sinkDir := os.Getenv("STANDALONE_SINK_DIR")
		if sinkDir == "" {
			sinkDir = "./sink"
		}
		var err error
		sink, err = newLocalSink(sinkDir)
		if err != nil {
			slog.Error("Failed to open standalone sink", "dir", sinkDir, "error", err)
			os.Exit(1)
		}
		deliver = sink.Forward
		syncForward = func(ctx context.Context, signal processor.AnonymizedSignal) error {
			payload, err := json.Marshal(signal)
			if err != nil {
				return fmt.Errorf("failed to encode signal: %w", err)
			}
			return sink.Forward(ctx, payload)
		}
		slog.Info("Standalone mode: signals are written locally, not forwarded anywhere", "sink_dir", sinkDir)
	}

	// Durable spool (recommended): /process persists anonymized signals and
	// returns 202; a background forwarder delivers them, so an outage of the
	// destination (vendor platform, or a full/unwritable sink disk) neither
	// loses signals nor blocks the core banking system.
	var sp *spool.Spool
	if spoolDir := os.Getenv("SPOOL_DIR"); spoolDir != "" {
		maxDepth := 10000
		if v := os.Getenv("SPOOL_MAX_DEPTH"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				maxDepth = n
			}
		}
		var err error
		sp, err = spool.New(spoolDir, maxDepth, deliver, adapters.IsPermanent, spool.Hooks{
			OnDelivered: func() { adapters.RecordMetric("signals_forwarded", 1) },
			OnDead:      func() { adapters.RecordMetric("signals_dead_lettered", 1) },
			OnDepth:     func(d int) { adapters.SetGauge("spool_depth", int64(d)) },
		})
		if err != nil {
			slog.Error("Failed to open spool", "dir", spoolDir, "error", err)
			os.Exit(1)
		}
		slog.Info("Durable spool enabled", "dir", spoolDir, "max_depth", maxDepth, "pending", sp.Depth())
	} else if cfg.IsStandalone() {
		slog.Warn("SPOOL_DIR not set - writing to the local sink synchronously; a slow/unwritable disk blocks /process")
	} else {
		slog.Warn("SPOOL_DIR not set - forwarding synchronously; signals are lost if the destination is down")
	}

	slog.Info("Starting Edge Gateway",
		"port", port,
		"mode", cfg.Mode,
		"institution_id", cfg.Hub.InstitutionID,
		"hub_url", cfg.Hub.HubEndpointURL,
	)

	mux := http.NewServeMux()

	mux.HandleFunc("/health", adapters.HealthCheckHandler)
	mux.HandleFunc("/metrics", adapters.MetricsHandler)
	mux.Handle("/process", middleware.RequireAPIKey(processTransaction(sp, syncForward), inboundKey))

	// Wrap with request logging and body size limit middleware
	handler := middleware.RequestLogger(middleware.MaxBodySize(mux, 1<<20)) // 1MB limit

	server := &http.Server{
		Addr:         ":" + port,
		Handler:      handler,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Background forwarder for the spool. Undelivered signals stay on disk
	// across restarts, so stopping it on shutdown is safe.
	forwardCtx, stopForwarder := context.WithCancel(context.Background())
	forwarderDone := make(chan struct{})
	if sp != nil {
		go func() {
			sp.Run(forwardCtx)
			close(forwarderDone)
		}()
	} else {
		close(forwarderDone)
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
	stopForwarder()
	<-forwarderDone
	if sp != nil && sp.Depth() > 0 {
		slog.Info("Undelivered signals remain spooled for next start", "pending", sp.Depth())
	}
	if sink != nil {
		if err := sink.Close(); err != nil {
			slog.Warn("Failed to close standalone sink cleanly", "error", err)
		}
	}
	slog.Info("Server stopped")
}

// validateStartup returns a human-readable problem for every required
// setting that is missing, given the selected GATEWAY_MODE. institution_id
// and bank_salt are always required - they drive local pseudonymization
// regardless of where (or whether) signals go. Everything needed only to
// reach an external vendor platform (API key, destination URL, HMAC secret)
// is required in middleware mode and not required at all in standalone mode.
//
// REGIONAL_PEPPER keys the global-scope mosaic derivation that exists to let
// a peer bank derive the same pseudonym; that only matters in middleware mode
// (see CLAUDE.md), so it stays required there for backward compatibility and
// is not required in standalone mode.
func validateStartup(cfg *config.GatewayConfig) []string {
	var problems []string

	if cfg.Hub.InstitutionID == "" {
		problems = append(problems, "Required hub.institution_id is not set (set INSTITUTION_ID or provide config file)")
	}
	if cfg.Local.BankSalt == "" {
		problems = append(problems, "Required local.bank_salt is not set (set BANK_SALT or provide config file)")
	}

	switch cfg.Mode {
	case config.ModeStandalone:
		// No external platform: hub.api_key, HUB_API_URL, HMAC_SECRET and
		// REGIONAL_PEPPER are not needed - signals go to the local sink.
	case config.ModeMiddleware:
		if cfg.Hub.APIKey == "" {
			problems = append(problems, "Required hub.api_key is not set (set API_KEY or provide config file) - required in middleware mode")
		}
		if cfg.Hub.HubEndpointURL == "" {
			problems = append(problems, "Required hub.hub_endpoint_url is not set (set HUB_API_URL or provide config file) - middleware mode has no destination to forward signals to")
		}
		if os.Getenv("HMAC_SECRET") == "" {
			problems = append(problems, "Required HMAC_SECRET is not set - every forward to the vendor platform would fail (required in middleware mode)")
		}
		if os.Getenv("REGIONAL_PEPPER") == "" {
			problems = append(problems, "Required REGIONAL_PEPPER is not set - it keys the global identity mosaics (required in middleware mode); set GATEWAY_MODE=standalone if there is no external platform")
		}
	default:
		problems = append(problems, fmt.Sprintf("Unknown GATEWAY_MODE %q - must be %q or %q", cfg.Mode, config.ModeMiddleware, config.ModeStandalone))
	}

	return problems
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

// processTransaction validates, anonymizes, and hands off one transaction.
// With a spool: persist and return 202 Accepted (delivery is asynchronous).
// Without: deliver synchronously via syncForward and return 200/502.
// syncForward is mode-dependent: middleware forwards to the vendor platform
// with bounded retry, standalone writes to the local sink.
func processTransaction(sp *spool.Spool, syncForward func(ctx context.Context, signal processor.AnonymizedSignal) error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
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

		if sp != nil {
			payload, err := json.Marshal(anonymized)
			if err != nil {
				http.Error(w, "Failed to encode signal", http.StatusInternalServerError)
				return
			}
			if err := sp.Enqueue(payload); err != nil {
				adapters.RecordMetric("spool_rejects", 1)
				if errors.Is(err, spool.ErrFull) {
					slog.Error("Spool full, rejecting signal", "depth", sp.Depth())
					http.Error(w, "Signal queue full, retry later", http.StatusServiceUnavailable)
				} else {
					slog.Error("Failed to spool signal", "error", err)
					http.Error(w, "Failed to queue signal", http.StatusInternalServerError)
				}
				return
			}
			adapters.RecordMetric("signals_processed", 1)
			slog.Info("Transaction queued",
				"mosaic_prefix", anonymized.IdentityMosaic[:16],
				"mosaic_scope", anonymized.MosaicScope,
				"amount_tier", anonymized.Metadata["amount_tier"],
				"spool_depth", sp.Depth(),
			)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusAccepted)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"status":          "queued",
				"signal_id":       anonymized.SignalID,
				"identity_mosaic": anonymized.IdentityMosaic[:16] + "...",
				"mosaic_scope":    anonymized.MosaicScope,
				"spool_depth":     sp.Depth(),
			})
			return
		}

		// Synchronous mode: deliver now (Hub forward with bounded retry in
		// middleware mode, or a local sink write in standalone mode).
		if err := syncForward(r.Context(), anonymized); err != nil {
			slog.Error("Failed to deliver signal",
				"error", err,
				"institution_id", anonymized.InstitutionID,
				"mosaic_prefix", anonymized.IdentityMosaic[:16],
			)
			adapters.RecordMetric("forward_failures", 1)
			http.Error(w, "Failed to deliver signal: "+err.Error(), http.StatusBadGateway)
			return
		}

		processingTime := time.Since(startTime)
		adapters.RecordMetric("signals_processed", 1)
		adapters.RecordMetric("processing_time_ms_total", processingTime.Milliseconds())

		slog.Info("Transaction processed",
			"processing_time", processingTime.String(),
			"mosaic_prefix", anonymized.IdentityMosaic[:16],
			"mosaic_scope", anonymized.MosaicScope,
			"institution_id", anonymized.InstitutionID,
			"amount_tier", anonymized.Metadata["amount_tier"],
		)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":             "processed",
			"processing_time_ms": processingTime.Milliseconds(),
			"signal_id":          anonymized.SignalID,
			"identity_mosaic":    anonymized.IdentityMosaic[:16] + "...",
			"mosaic_scope":       anonymized.MosaicScope,
		})
	}
}
