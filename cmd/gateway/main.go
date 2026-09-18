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
	"github.com/papoveB01/EdgeGW_Project/internal/auditlog"
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

	// Pepper input for mosaic derivation - see resolvePepper. May be empty:
	// in MOSAIC_KEYING=bank (default) it's optional additional keying
	// material, since BANK_SALT is always folded in. In
	// MOSAIC_KEYING=regional, validateStartup already guarantees it's
	// non-empty by the time we get here.
	pepper := resolvePepper()
	switch {
	case cfg.MosaicKeying == config.MosaicKeyingRegional:
		slog.Info("MOSAIC_KEYING=regional: identity/destination mosaics derived from a national ID are keyed on the shared pepper alone and are derivable cross-gateway by anyone holding it")
	case pepper == "":
		slog.Info("MOSAIC_KEYING=bank (default): pepper not set, mosaics keyed by BANK_SALT alone - this is not a weakened mosaic, BANK_SALT is always folded in")
	default:
		slog.Info("MOSAIC_KEYING=bank (default): pepper set, folded in alongside BANK_SALT as additional key material")
	}

	// Delivery destination: middleware forwards one-way to the external
	// vendor platform; standalone has no external system, so signals are
	// written to a local durable sink instead. Either way, "forward now"
	// (sync) or "forward later" (spool) always lands somewhere on disk or
	// with the vendor - there is no silent no-op / discard path.
	//
	// deliver is the spool's background forwarder: single-attempt, because
	// the spool itself already retries (with its own backoff) across
	// restarts. syncDeliverBytes is its synchronous-mode (no SPOOL_DIR)
	// counterpart, and does get a bounded retry wrapper in middleware mode
	// - a network call to a remote vendor can fail transiently; see the
	// standalone branch below for why that wrapper isn't used there. Both
	// operate on already-marshaled bytes rather than the signal struct
	// directly, so that whatever wraps them for the audit trail below
	// hashes exactly the bytes transmitted, never a second, separately
	// re-marshaled copy of them (see auditingForward / auditingSyncForward
	// doc comments).
	var sink *localSink
	deliver := spool.ForwardFunc(adapters.ForwardPayload)
	syncDeliverBytes := spool.ForwardFunc(func(ctx context.Context, payload []byte) error {
		return adapters.ForwardPayloadWithRetry(ctx, payload, 2)
	})
	// destination identifies, for the audit trail below, where signals
	// actually go: the vendor URL in middleware mode, or the standalone
	// sink's directory. Resolved once here (same place deliver/
	// syncDeliverBytes are resolved) rather than re-read per record.
	destination := cfg.Hub.HubEndpointURL
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
		destination = "local-sink:" + sinkDir
		deliver = sink.Forward
		// No bounded-retry wrapper here, unlike middleware's
		// ForwardPayloadWithRetry: middleware retries because a network call
		// to a remote vendor can fail transiently; a local disk write either
		// succeeds or fails for a reason (permissions, full disk) that a few
		// immediate retries won't fix. A failure here still returns 502 to
		// the caller, and SPOOL_DIR remains the right way to ride out a
		// sink outage rather than retrying synchronously in the request path.
		syncDeliverBytes = sink.Forward
		slog.Info("Standalone mode: signals are written locally, not forwarded anywhere", "sink_dir", sinkDir)
	}

	// Durable egress audit log: a record written ONLY after a destination
	// confirms delivery, surviving both process restarts and spool deletion
	// (internal/spool removes a signal's file the instant delivery
	// succeeds, so it is never evidence of what left the bank - see
	// internal/auditlog's package doc). Without this, nothing durable
	// answers "show me everything you sent this vendor last quarter".
	//
	// Default is disabled with a loud startup warning, mirroring SPOOL_DIR:
	// audit records are compliance infrastructure that changes what a
	// regulator can be shown, not a default-on convenience, and an operator
	// who hasn't provisioned a directory (and its retention policy - this
	// package never rotates or expires records, same as the standalone
	// sink) for permanent personal-data records shouldn't get one silently
	// created under their working directory.
	var auditLogger *auditlog.Logger
	// redeliverGuard backs auditingForward's retry-storm bound (see that
	// function's doc comment). It must be cleared whenever the spool
	// dead-letters an item WITHOUT going through auditingForward's closure
	// (forwardOldest's unreadable-spool-file branch does exactly that) - see
	// redeliveryGuard's doc comment for why a stale guard would otherwise
	// risk a FALSE "delivered" audit record. Declared here (nil until the
	// audit block below possibly sets it) so the spool's OnDead hook, wired
	// further down, can reach it regardless of whether audit logging is
	// enabled.
	var redeliverGuard *redeliveryGuard
	if auditDir := os.Getenv("EGRESS_AUDIT_DIR"); auditDir != "" {
		storePayload := os.Getenv("EGRESS_AUDIT_STORE_PAYLOAD") == "true"
		var err error
		// auditlog.New itself probes that auditDir is actually writable
		// (not just that it exists), so a misconfigured mount fails here,
		// at startup, rather than at the first confirmed delivery.
		auditLogger, err = auditlog.New(auditDir, storePayload)
		if err != nil {
			slog.Error("Failed to open egress audit log", "dir", auditDir, "error", err)
			os.Exit(1)
		}
		// health is shared by both wrappers below so ONE readiness signal
		// (see internal/adapters.SetReadinessAuditStatus) reflects either
		// delivery path's audit write getting stuck - synchronous mode has
		// no other automatic degradation signal the way the spool has
		// staleness.
		health := newAuditHealth()
		redeliverGuard = newRedeliveryGuard()
		deliver = auditingForward(deliver, auditLogger, destination, health, redeliverGuard)
		syncDeliverBytes = auditingSyncForward(syncDeliverBytes, auditLogger, destination, health)
		adapters.SetReadinessAuditStatus(func() adapters.AuditStatus { return health.status() })
		slog.Info("Egress audit log enabled", "dir", auditDir, "store_full_payload", storePayload, "destination", destination)
	} else {
		slog.Warn("EGRESS_AUDIT_DIR not set - confirmed deliveries are not durably recorded; an auditor cannot be shown what left the bank")
	}

	// syncForward is the signal-typed entry point processTransaction calls
	// in synchronous (no SPOOL_DIR) mode. It marshals exactly once and
	// hands the resulting bytes to syncDeliverBytes - by this point
	// possibly wrapped with audit logging above - so the same bytes are
	// both transmitted and (if audit logging is enabled) hashed for the
	// audit record.
	syncForward := func(ctx context.Context, signal processor.AnonymizedSignal) error {
		payload, err := json.Marshal(signal)
		if err != nil {
			return fmt.Errorf("failed to encode signal: %w", err)
		}
		return syncDeliverBytes(ctx, payload)
	}

	// Readiness thresholds: egress is one-way (no score ever comes back
	// through the gateway), so /readyz and /metrics are the only way to
	// tell a healthy feed from one stuck hours behind. Read directly from
	// the environment rather than internal/config so this stays a
	// self-contained observability concern.
	//
	// This is deliberately NOT wired to /health (liveness): a full or
	// stale spool during a vendor outage is the durable queue working as
	// designed, not a dead process, and restarting fixes neither. See
	// ReadinessCheckHandler's doc comment in internal/adapters/inbound.go.
	readinessMaxDepthRatio := adapters.DefaultReadinessMaxDepthRatio
	if v := os.Getenv("READINESS_MAX_DEPTH_RATIO"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil && f > 0 && f <= 1 {
			readinessMaxDepthRatio = f
		}
	}
	readinessMaxStaleness := adapters.DefaultReadinessMaxStaleness
	if v := os.Getenv("READINESS_MAX_STALENESS_SECONDS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			readinessMaxStaleness = time.Duration(n) * time.Second
		}
	}
	adapters.SetReadinessThresholds(readinessMaxDepthRatio, readinessMaxStaleness)
	if v := os.Getenv("READINESS_MAX_AUDIT_FAILURES"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			adapters.SetReadinessMaxAuditFailures(n)
		}
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
			OnDelivered: func(queueTime time.Duration) { adapters.RecordDelivery(queueTime) },
			OnDead: func() {
				adapters.RecordMetric("signals_dead_lettered", 1)
				// Any dead-letter event means an item just left the queue
				// - including via forwardOldest's unreadable-spool-file
				// branch, which bypasses auditingForward's closure
				// entirely. redeliverGuard must forget whatever it was
				// holding so a later, byte-identical payload can't be
				// mistaken for "already delivered" - see
				// redeliveryGuard's doc comment. nil (no
				// EGRESS_AUDIT_DIR configured) is a safe no-op.
				if redeliverGuard != nil {
					redeliverGuard.clear()
				}
			},
			OnFailed: func() { adapters.RecordMetric("delivery_attempt_failures", 1) },
			OnDepth:  func(d int) { adapters.SetGauge("spool_depth", int64(d)) },
			OnOldestPendingAge: func(ageSeconds float64) {
				adapters.SetGauge("spool_oldest_pending_age_seconds", int64(ageSeconds))
			},
		})
		if err != nil {
			slog.Error("Failed to open spool", "dir", spoolDir, "error", err)
			os.Exit(1)
		}
		adapters.SetGauge("spool_max_depth", int64(maxDepth))
		adapters.SetReadinessSpoolStatus(func() adapters.SpoolStatus {
			age, hasPending := sp.OldestPendingAge(time.Now())
			return adapters.SpoolStatus{
				Depth:            sp.Depth(),
				MaxDepth:         sp.MaxDepth(),
				OldestPendingAge: age,
				HasPending:       hasPending,
			}
		})
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

	// /health is LIVENESS only (safe to wire to an auto-restart action);
	// /readyz reports degradation (spool backlog/staleness) and must never
	// be wired to auto-restart — see both handlers' doc comments.
	mux.HandleFunc("/health", adapters.HealthCheckHandler)
	mux.HandleFunc("/readyz", adapters.ReadinessCheckHandler)
	mux.HandleFunc("/metrics", adapters.MetricsHandler)
	mux.Handle("/process", middleware.RequireAPIKey(processTransaction(sp, syncForward, pepper), inboundKey))

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
	if auditLogger != nil {
		if err := auditLogger.Close(); err != nil {
			slog.Warn("Failed to close egress audit log cleanly", "error", err)
		}
	}
	slog.Info("Server stopped")
}

// validateStartup returns a human-readable problem for every required
// setting that is missing, given the selected GATEWAY_MODE and
// MOSAIC_KEYING. institution_id and bank_salt are always required - they
// drive local pseudonymization regardless of where (or whether) signals go.
// Everything needed only to reach an external vendor platform (API key,
// destination URL, HMAC secret) is required in middleware mode and not
// required at all in standalone mode.
//
// The pepper (MOSAIC_PEPPER, or its backward-compatible alias
// REGIONAL_PEPPER - see pepperEnv) is a separate, orthogonal requirement
// keyed off MOSAIC_KEYING, not GATEWAY_MODE: it is REQUIRED when
// MOSAIC_KEYING=regional (that mode's whole point is cross-gateway
// derivability, which needs a shared secret) and OPTIONAL when
// MOSAIC_KEYING=bank, the default (every mosaic already folds in this
// institution's own BANK_SALT - see internal/processor.mosaicKeyMaterial -
// so an unset pepper there is not an empty-key-HMAC risk the way it was
// before this mosaic scheme existed).
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
		// No external platform: hub.api_key, HUB_API_URL and HMAC_SECRET are
		// not needed - signals go to the local sink.
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
	default:
		problems = append(problems, fmt.Sprintf("Unknown GATEWAY_MODE %q - must be %q or %q", cfg.Mode, config.ModeMiddleware, config.ModeStandalone))
	}

	switch cfg.MosaicKeying {
	case config.MosaicKeyingBank:
		// Pepper is optional - BANK_SALT alone is always folded into the key.
	case config.MosaicKeyingRegional:
		if pepperEnv() == "" {
			problems = append(problems, "Required MOSAIC_PEPPER (or its alias REGIONAL_PEPPER) is not set - MOSAIC_KEYING=regional keys national-ID mosaics on the shared pepper alone, so it must be set for cross-gateway derivability to work at all; set MOSAIC_KEYING=bank if there is no shared pepper")
		}
	default:
		problems = append(problems, fmt.Sprintf("Unknown MOSAIC_KEYING %q - must be %q or %q", cfg.MosaicKeying, config.MosaicKeyingBank, config.MosaicKeyingRegional))
	}

	return problems
}

// pepperEnv returns the configured mosaic pepper. MOSAIC_PEPPER is the
// preferred name: REGIONAL_PEPPER described this as exclusively a
// cross-region/cross-bank matching key, which stopped being accurate once
// the pepper became optional additional keying material in the default
// bank-scoped mode rather than the sole key for global mosaics.
// REGIONAL_PEPPER is still accepted as a backward-compatible alias so
// existing deployments' env/config don't break. If both are set,
// MOSAIC_PEPPER wins.
func pepperEnv() string {
	if v := os.Getenv("MOSAIC_PEPPER"); v != "" {
		return v
	}
	return os.Getenv("REGIONAL_PEPPER")
}

// resolvePepper returns the pepper value passed into
// processor.AnonymizeSignal as additional key material for mosaic
// derivation. It may be empty - see validateStartup for when that's
// required to not be the case (MOSAIC_KEYING=regional) versus fine
// (MOSAIC_KEYING=bank, the default, where BANK_SALT alone already keys the
// mosaic).
func resolvePepper() string {
	return pepperEnv()
}

// healthcheck probes the local /health (liveness) endpoint and returns a
// process exit code. This backs the Docker HEALTHCHECK in
// deployments/docker-compose.yml, and a non-zero exit is what an
// orchestrator or autoheal sidecar would act on to restart the container.
// It must keep pointing at /health, never /readyz: readiness/degradation
// (spool backlog or staleness) is not something a restart can fix, and
// restarting for it would only add a self-inflicted /process outage on top
// of a vendor outage the spool already exists to absorb.
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

// genSignalID is processor.NewSignalID by default. processTransaction calls
// it (never processor.NewSignalID directly) so tests can inject a failing
// entropy source and exercise the 500 path deterministically, without
// patching crypto/rand globally or resorting to unsafe tricks - the same
// swappable-function approach processor.newSignalIDFrom uses internally.
// This is a testing seam, not something the compiler enforces: production
// code should never reassign it.
var genSignalID = processor.NewSignalID

// processTransaction validates, anonymizes, and hands off one transaction.
// With a spool: persist and return 202 Accepted (delivery is asynchronous).
// Without: deliver synchronously via syncForward and return 200/502.
// syncForward is mode-dependent: middleware forwards to the vendor platform
// with bounded retry, standalone writes to the local sink. pepper is
// additional key material for mosaic derivation, resolved once at startup
// (see main) - it may be empty (see resolvePepper/validateStartup).
//
// AnonymizeSignal is a pure function and no longer generates the random
// fallback signal_id itself (see its doc comment): when RawData.
// TransactionRef is absent, this handler generates that ID via
// genSignalID() BEFORE calling AnonymizeSignal, and handles a crypto/rand
// failure the same way every other failure branch here does - slog.Error
// with no PII, a distinct metric, and a proper 500 - instead of letting a
// panic reach net/http's per-connection recover (see
// https://github.com/papoveB01/EdgeGW_Project/issues/4).
func processTransaction(sp *spool.Spool, syncForward func(ctx context.Context, signal processor.AnonymizedSignal) error, pepper string) http.HandlerFunc {
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

		// AnonymizeSignal needs a random fallback signal_id only when the
		// caller didn't supply transaction_ref - generate it here, up
		// front, so a crypto/rand failure surfaces as a normal request
		// failure rather than a panic inside a "pure" function.
		// processor.NeedsFallbackSignalID is the single, shared definition
		// of "absent" (blank/whitespace-only counts as absent) - both this
		// check and AnonymizeSignal's internal branch call it, so the two
		// can't independently drift out of agreement. See that function's
		// doc comment.
		var fallbackSignalID string
		if processor.NeedsFallbackSignalID(rawData.TransactionRef) {
			id, err := genSignalID()
			if err != nil {
				// No PII in this log line - err is a wrapped crypto/rand
				// failure with no request data in it.
				slog.Error("Failed to generate signal_id", "error", err)
				adapters.RecordMetric("signal_id_generation_failures", 1)
				http.Error(w, "Failed to generate signal_id", http.StatusInternalServerError)
				return
			}
			fallbackSignalID = id
		}

		anonymized := processor.AnonymizeSignal(*rawData, cfg.Hub.InstitutionID, salt, pepper, cfg.MosaicKeying, cfg.Local.ReportingThreshold, fallbackSignalID)

		// Contract-violation guard, mirroring processor.MissingSignalIDSentinel's
		// doc comment: this should be unreachable given the code right
		// above (fallbackSignalID is always populated via genSignalID
		// whenever NeedsFallbackSignalID is true, and this handler returns
		// 500 itself if that generation fails). It is checked anyway
		// because AnonymizeSignal has other/future callers this handler
		// can't see, and a silent "" signal_id landing in the vendor
		// payload AND the append-only audit record is a much worse outcome
		// than one loud log line for a case that should never fire.
		if anonymized.SignalID == processor.MissingSignalIDSentinel {
			slog.Warn("signal_id fell back to sentinel - fallbackSignalID was unexpectedly blank",
				"institution_id", anonymized.InstitutionID,
			)
			adapters.RecordMetric("signal_id_missing_fallback", 1)
		}

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
