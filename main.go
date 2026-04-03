package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"edge-gateway/adapters"
	"edge-gateway/config"
	"edge-gateway/processor"
)

// Prometheus-compatible metrics counters
var (
	requestsTotal   int64
	requestsSuccess int64
	requestsFailed  int64
	hubForwardTotal int64
	hubForwardFails int64
	rateLimitHits   int64
)

func main() {
	// Load config from env and optional config file (e.g. Docker volume)
	cfg := config.Load()

	port := os.Getenv("GATEWAY_PORT")
	if port == "" {
		port = "8080"
	}

	// Validate required Hub params (from Hub UI or config file)
	if cfg.Hub.InstitutionID == "" {
		log.Fatal("Required hub.institution_id is not set (set INSTITUTION_ID or provide config file)")
	}
	if cfg.Hub.APIKey == "" {
		log.Fatal("Required hub.api_key is not set (set API_KEY or provide config file)")
	}
	if cfg.Hub.HubEndpointURL == "" {
		log.Fatal("Required hub.hub_endpoint_url is not set (set HUB_API_URL or provide config file)")
	}
	// HMAC_SECRET can come from env (Hub provides it at onboarding; not in config file for security)
	if os.Getenv("HMAC_SECRET") == "" && cfg.Hub.APIKey != "" {
		log.Print("Warning: HMAC_SECRET not set - payload signing will fail unless set via env")
	}
	if cfg.Local.BankSalt == "" {
		log.Fatal("Required local.bank_salt is not set (set BANK_SALT or provide config file)")
	}
	if os.Getenv("REGIONAL_PEPPER") == "" {
		log.Print("Warning: REGIONAL_PEPPER not set - use Hub-provided value for production")
	}

	log.Printf("Starting Edge Gateway on port %s", port)
	log.Printf("Institution ID: %s", cfg.Hub.InstitutionID)
	log.Printf("Hub API URL: %s", cfg.Hub.HubEndpointURL)
	log.Printf("API Key: [REDACTED] (len=%d)", len(cfg.Hub.APIKey))

	// Create a mux for better routing
	mux := http.NewServeMux()

	// Health check endpoint
	mux.HandleFunc("/health", adapters.HealthCheckHandler)
	log.Printf("Health endpoint registered at /health")

	// Metrics endpoint (Prometheus-compatible)
	mux.HandleFunc("/metrics", metricsHandler)
	log.Printf("Metrics endpoint registered at /metrics")

	// Main transaction processing endpoint (rate-limited)
	processLimiter := newRateLimiter(100, 200) // 100 req/s, burst of 200
	mux.HandleFunc("/process", rateLimitMiddleware(processLimiter, processTransaction))
	log.Printf("Process endpoint registered at /process (rate-limited: 100 req/s, burst 200)")

	// Banking Portal: resolve identity_mosaic to local PII for SAR re-association (compliance officer only)
	mux.HandleFunc("/resolve-pii", resolvePII)
	log.Printf("Resolve-PII endpoint registered at /resolve-pii")

	// Landing page: serve static files
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		http.ServeFile(w, r, "static/index.html")
	})
	log.Printf("Landing page registered at /")

	// Configure server with TLS settings
	server := &http.Server{
		Addr:         ":" + port,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}

	// Start server in goroutine for graceful shutdown support
	go func() {
		certFile := os.Getenv("TLS_CERT_FILE")
		keyFile := os.Getenv("TLS_KEY_FILE")
		var err error
		if certFile != "" && keyFile != "" {
			log.Printf("TLS enabled (cert=%s)", certFile)
			err = server.ListenAndServeTLS(certFile, keyFile)
		} else {
			log.Print("WARNING: TLS not configured — set TLS_CERT_FILE and TLS_KEY_FILE for production")
			err = server.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server failed: %v", err)
		}
	}()

	log.Printf("Server started on :%s", port)

	// Wait for interrupt signal for graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	sig := <-quit
	log.Printf("Received signal %v, shutting down gracefully...", sig)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}
	log.Print("Server exited cleanly")
}

func processTransaction(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	atomic.AddInt64(&requestsTotal, 1)
	log.Printf("Received transaction request from %s", r.RemoteAddr)

	// Only accept POST requests
	if r.Method != http.MethodPost {
		log.Printf("Rejected non-POST request: %s", r.Method)
		atomic.AddInt64(&requestsFailed, 1)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	log.Printf("Processing transaction request...")

	// Parse incoming request
	rawDataMap, err := adapters.ProcessInboundRequest(r)
	if err != nil {
		log.Printf("Error processing request: %v", err)
		atomic.AddInt64(&requestsFailed, 1)
		http.Error(w, "Invalid request: "+err.Error(), http.StatusBadRequest)
		return
	}

	log.Printf("Request parsed successfully")

	// Convert to RawData struct
	rawDataJSON, err := json.Marshal(rawDataMap)
	if err != nil {
		log.Printf("Error marshaling raw data map: %v", err)
		atomic.AddInt64(&requestsFailed, 1)
		http.Error(w, "Internal error processing request data", http.StatusInternalServerError)
		return
	}
	var rawData processor.RawData
	if err := json.Unmarshal(rawDataJSON, &rawData); err != nil {
		log.Printf("Error unmarshaling raw data: %v", err)
		atomic.AddInt64(&requestsFailed, 1)
		http.Error(w, "Invalid data format", http.StatusBadRequest)
		return
	}

	// Get salt and pepper from config (local params) and env
	cfg := config.Get()
	salt := cfg.Local.BankSalt
	pepper := os.Getenv("REGIONAL_PEPPER")

	log.Printf("Anonymizing signal...")

	// Anonymize the signal (institution_id from Hub config; reporting threshold for is_near_threshold / Multi-Bank Structuring)
	reportingThreshold := cfg.Local.ReportingThreshold
	if reportingThreshold <= 0 {
		reportingThreshold = 10000
	}
	anonymized := processor.AnonymizeSignal(rawData, cfg.Hub.InstitutionID, salt, pepper, reportingThreshold)

	mosaicPreview := processor.TruncateMosaic(anonymized.IdentityMosaic, 16)
	log.Printf("Signal anonymized, forwarding to hub at %s...", cfg.Hub.HubEndpointURL)

	// Forward to Hub
	atomic.AddInt64(&hubForwardTotal, 1)
	if err := adapters.ForwardToHub(anonymized); err != nil {
		log.Printf("ERROR forwarding to hub: %v", err)
		log.Printf("  Institution: %s", anonymized.InstitutionID)
		log.Printf("  Mosaic: %s...", mosaicPreview)
		atomic.AddInt64(&hubForwardFails, 1)
		atomic.AddInt64(&requestsFailed, 1)
		http.Error(w, "Failed to forward signal to hub: "+err.Error(), http.StatusInternalServerError)
		return
	}

	log.Printf("SUCCESS: Transaction forwarded to hub - Mosaic: %s...", mosaicPreview)

	// Calculate processing time
	processingTime := time.Since(startTime)

	// Return success response
	atomic.AddInt64(&requestsSuccess, 1)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":             "processed",
		"processing_time_ms": processingTime.Milliseconds(),
		"identity_mosaic":    mosaicPreview + "...", // Show first 16 chars only
	})

	log.Printf("Transaction processed in %v - Mosaic: %s...", processingTime, mosaicPreview)
}

// resolvePII handles Banking Portal re-association: map identity_mosaic to local customer/account (PII never sent to Hub).
// In production, the bank wires this to their internal re-identification service or local audit store.
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
		http.Error(w, "officer_token is required", http.StatusUnauthorized)
		return
	}

	// Validate officer_token using HMAC-SHA256(mosaic, OFFICER_AUTH_SECRET)
	officerSecret := os.Getenv("OFFICER_AUTH_SECRET")
	if officerSecret == "" {
		log.Print("ERROR: OFFICER_AUTH_SECRET not set — /resolve-pii is disabled")
		http.Error(w, "PII resolution not configured", http.StatusServiceUnavailable)
		return
	}

	mac := hmac.New(sha256.New, []byte(officerSecret))
	mac.Write([]byte(body.Mosaic))
	expectedToken := hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(body.OfficerToken), []byte(expectedToken)) {
		log.Printf("SECURITY: Invalid officer_token for /resolve-pii from %s", r.RemoteAddr)
		http.Error(w, "Invalid officer_token", http.StatusForbidden)
		return
	}

	// In production: lookup mosaic in local DB/store
	// For demo: return mock local PII so the Portal UI can display "local resolution" flow
	suffix := body.Mosaic
	if len(suffix) > 8 {
		suffix = suffix[len(suffix)-8:]
	}
	mock := map[string]interface{}{
		"customer_id":   "LOCAL-" + suffix,
		"account_id":    "***4567",
		"name_redacted": "*** (resolved locally)",
		"resolved_at":   time.Now().UTC().Format(time.RFC3339),
		"note":          "Demo: In production this would be real PII from your local audit store.",
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(mock)
}

// --- Rate Limiter (token-bucket) ---

type rateLimiter struct {
	mu         sync.Mutex
	tokens     float64
	maxTokens  float64
	refillRate float64 // tokens per second
	lastTime   time.Time
}

func newRateLimiter(rps float64, burst int) *rateLimiter {
	return &rateLimiter{
		tokens:     float64(burst),
		maxTokens:  float64(burst),
		refillRate: rps,
		lastTime:   time.Now(),
	}
}

func (rl *rateLimiter) allow() bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(rl.lastTime).Seconds()
	rl.tokens += elapsed * rl.refillRate
	if rl.tokens > rl.maxTokens {
		rl.tokens = rl.maxTokens
	}
	rl.lastTime = now

	if rl.tokens >= 1 {
		rl.tokens--
		return true
	}
	return false
}

func rateLimitMiddleware(rl *rateLimiter, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !rl.allow() {
			atomic.AddInt64(&rateLimitHits, 1)
			http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		next(w, r)
	}
}

// --- Metrics ---

func metricsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	fmt.Fprintf(w, "# HELP edge_gateway_requests_total Total requests to /process\n")
	fmt.Fprintf(w, "# TYPE edge_gateway_requests_total counter\n")
	fmt.Fprintf(w, "edge_gateway_requests_total %d\n", atomic.LoadInt64(&requestsTotal))
	fmt.Fprintf(w, "# HELP edge_gateway_requests_success Successful /process requests\n")
	fmt.Fprintf(w, "# TYPE edge_gateway_requests_success counter\n")
	fmt.Fprintf(w, "edge_gateway_requests_success %d\n", atomic.LoadInt64(&requestsSuccess))
	fmt.Fprintf(w, "# HELP edge_gateway_requests_failed Failed /process requests\n")
	fmt.Fprintf(w, "# TYPE edge_gateway_requests_failed counter\n")
	fmt.Fprintf(w, "edge_gateway_requests_failed %d\n", atomic.LoadInt64(&requestsFailed))
	fmt.Fprintf(w, "# HELP edge_gateway_hub_forwards_total Total hub forward attempts\n")
	fmt.Fprintf(w, "# TYPE edge_gateway_hub_forwards_total counter\n")
	fmt.Fprintf(w, "edge_gateway_hub_forwards_total %d\n", atomic.LoadInt64(&hubForwardTotal))
	fmt.Fprintf(w, "# HELP edge_gateway_hub_forward_failures Hub forward failures\n")
	fmt.Fprintf(w, "# TYPE edge_gateway_hub_forward_failures counter\n")
	fmt.Fprintf(w, "edge_gateway_hub_forward_failures %d\n", atomic.LoadInt64(&hubForwardFails))
	fmt.Fprintf(w, "# HELP edge_gateway_rate_limit_hits Rate limit rejections\n")
	fmt.Fprintf(w, "# TYPE edge_gateway_rate_limit_hits counter\n")
	fmt.Fprintf(w, "edge_gateway_rate_limit_hits %d\n", atomic.LoadInt64(&rateLimitHits))
}
