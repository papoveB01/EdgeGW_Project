package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/papoveB01/EdgeGW_Project/internal/config"
	"github.com/papoveB01/EdgeGW_Project/internal/processor"
	"github.com/papoveB01/EdgeGW_Project/internal/spool"
)

func TestValidateStartup_StandaloneStartsWithoutPepperOrDestination(t *testing.T) {
	t.Setenv("REGIONAL_PEPPER", "")
	t.Setenv("MOSAIC_PEPPER", "")
	t.Setenv("HUB_API_URL", "")
	t.Setenv("HMAC_SECRET", "")

	cfg := &config.GatewayConfig{
		Mode:         config.ModeStandalone,
		MosaicKeying: config.MosaicKeyingBank,
		Hub: config.HubParams{
			InstitutionID: "BANK_A",
			// APIKey and HubEndpointURL deliberately left empty.
		},
		Local: config.LocalParams{
			BankSalt: "a_sufficiently_long_bank_salt_value",
		},
	}

	if problems := validateStartup(cfg); len(problems) != 0 {
		t.Fatalf("expected standalone mode (bank keying) to start without REGIONAL_PEPPER/HUB_API_URL, got problems: %v", problems)
	}
}

func TestValidateStartup_StandaloneStillRequiresInstitutionAndSalt(t *testing.T) {
	cfg := &config.GatewayConfig{Mode: config.ModeStandalone, MosaicKeying: config.MosaicKeyingBank}

	problems := validateStartup(cfg)
	if len(problems) != 2 {
		t.Fatalf("expected 2 problems (institution_id, bank_salt), got %d: %v", len(problems), problems)
	}
}

func TestValidateStartup_MiddlewareFailsFastWithoutDestination(t *testing.T) {
	t.Setenv("HMAC_SECRET", "some_secret")

	cfg := &config.GatewayConfig{
		Mode:         config.ModeMiddleware,
		MosaicKeying: config.MosaicKeyingBank,
		Hub: config.HubParams{
			InstitutionID: "BANK_A",
			APIKey:        "some_api_key",
			// HubEndpointURL deliberately left empty - no destination configured.
		},
		Local: config.LocalParams{
			BankSalt: "a_sufficiently_long_bank_salt_value",
		},
	}

	problems := validateStartup(cfg)
	if len(problems) != 1 {
		t.Fatalf("expected exactly 1 problem (missing destination), got %d: %v", len(problems), problems)
	}
	if problems[0] == "" {
		t.Fatal("expected a non-empty, clear error message")
	}
}

func TestValidateStartup_MiddlewareRequiresHmacSecretButNotPepperInBankMode(t *testing.T) {
	// This replaces the pre-v3 TestValidateStartup_MiddlewareRequiresPepperAndHmacSecret:
	// the pepper requirement is no longer tied to GATEWAY_MODE=middleware at
	// all - it's tied to MOSAIC_KEYING=regional (see
	// TestValidateStartup_RegionalKeyingRequiresPepper below). In the
	// default bank keying mode, middleware mode with no pepper set must
	// report exactly the HMAC_SECRET problem, not a pepper one.
	t.Setenv("HMAC_SECRET", "")
	t.Setenv("REGIONAL_PEPPER", "")
	t.Setenv("MOSAIC_PEPPER", "")

	cfg := &config.GatewayConfig{
		Mode:         config.ModeMiddleware,
		MosaicKeying: config.MosaicKeyingBank,
		Hub: config.HubParams{
			InstitutionID:  "BANK_A",
			APIKey:         "some_api_key",
			HubEndpointURL: "https://vendor.example.com/api/v1/signals",
		},
		Local: config.LocalParams{
			BankSalt: "a_sufficiently_long_bank_salt_value",
		},
	}

	problems := validateStartup(cfg)
	if len(problems) != 1 {
		t.Fatalf("expected exactly 1 problem (HMAC_SECRET), got %d: %v", len(problems), problems)
	}
}

func TestValidateStartup_MiddlewareFullyConfiguredStartsClean(t *testing.T) {
	t.Setenv("HMAC_SECRET", "some_secret")

	cfg := &config.GatewayConfig{
		Mode:         config.ModeMiddleware,
		MosaicKeying: config.MosaicKeyingBank,
		Hub: config.HubParams{
			InstitutionID:  "BANK_A",
			APIKey:         "some_api_key",
			HubEndpointURL: "https://vendor.example.com/api/v1/signals",
		},
		Local: config.LocalParams{
			BankSalt: "a_sufficiently_long_bank_salt_value",
		},
	}

	if problems := validateStartup(cfg); len(problems) != 0 {
		t.Fatalf("expected fully-configured middleware+bank-keying mode to start clean, got problems: %v", problems)
	}
}

func TestValidateStartup_RegionalKeyingRequiresPepper(t *testing.T) {
	t.Setenv("HMAC_SECRET", "some_secret")
	t.Setenv("REGIONAL_PEPPER", "")
	t.Setenv("MOSAIC_PEPPER", "")

	cfg := &config.GatewayConfig{
		Mode:         config.ModeStandalone, // pepper requirement is independent of GATEWAY_MODE
		MosaicKeying: config.MosaicKeyingRegional,
		Hub: config.HubParams{
			InstitutionID: "BANK_A",
		},
		Local: config.LocalParams{
			BankSalt: "a_sufficiently_long_bank_salt_value",
		},
	}

	problems := validateStartup(cfg)
	if len(problems) != 1 {
		t.Fatalf("expected exactly 1 problem (missing pepper), got %d: %v", len(problems), problems)
	}
}

func TestValidateStartup_RegionalKeyingSatisfiedByLegacyRegionalPepper(t *testing.T) {
	t.Setenv("MOSAIC_PEPPER", "")
	t.Setenv("REGIONAL_PEPPER", "legacy_pepper_value")

	cfg := &config.GatewayConfig{
		Mode:         config.ModeStandalone,
		MosaicKeying: config.MosaicKeyingRegional,
		Hub: config.HubParams{
			InstitutionID: "BANK_A",
		},
		Local: config.LocalParams{
			BankSalt: "a_sufficiently_long_bank_salt_value",
		},
	}

	if problems := validateStartup(cfg); len(problems) != 0 {
		t.Fatalf("expected the legacy REGIONAL_PEPPER alias to satisfy regional keying, got problems: %v", problems)
	}
}

func TestValidateStartup_RegionalKeyingSatisfiedByMosaicPepper(t *testing.T) {
	t.Setenv("REGIONAL_PEPPER", "")
	t.Setenv("MOSAIC_PEPPER", "new_name_pepper_value")

	cfg := &config.GatewayConfig{
		Mode:         config.ModeStandalone,
		MosaicKeying: config.MosaicKeyingRegional,
		Hub: config.HubParams{
			InstitutionID: "BANK_A",
		},
		Local: config.LocalParams{
			BankSalt: "a_sufficiently_long_bank_salt_value",
		},
	}

	if problems := validateStartup(cfg); len(problems) != 0 {
		t.Fatalf("expected MOSAIC_PEPPER to satisfy regional keying, got problems: %v", problems)
	}
}

func TestValidateStartup_UnknownMosaicKeyingRejected(t *testing.T) {
	cfg := &config.GatewayConfig{
		Mode:         config.ModeStandalone,
		MosaicKeying: "bogus",
		Hub: config.HubParams{
			InstitutionID: "BANK_A",
		},
		Local: config.LocalParams{
			BankSalt: "a_sufficiently_long_bank_salt_value",
		},
	}

	problems := validateStartup(cfg)
	if len(problems) != 1 {
		t.Fatalf("expected exactly 1 problem (unknown mosaic keying), got %d: %v", len(problems), problems)
	}
}

func TestResolvePepper_PrefersMosaicPepperOverLegacyAlias(t *testing.T) {
	t.Setenv("MOSAIC_PEPPER", "new_name_value")
	t.Setenv("REGIONAL_PEPPER", "legacy_value")

	if got := resolvePepper(); got != "new_name_value" {
		t.Fatalf("expected MOSAIC_PEPPER to win when both are set, got %q", got)
	}
}

func TestResolvePepper_FallsBackToLegacyRegionalPepperAlias(t *testing.T) {
	t.Setenv("MOSAIC_PEPPER", "")
	t.Setenv("REGIONAL_PEPPER", "legacy_value")

	if got := resolvePepper(); got != "legacy_value" {
		t.Fatalf("expected REGIONAL_PEPPER to be accepted as a backward-compatible alias, got %q", got)
	}
}

func TestResolvePepper_EmptyWhenNeitherSet(t *testing.T) {
	t.Setenv("MOSAIC_PEPPER", "")
	t.Setenv("REGIONAL_PEPPER", "")

	if got := resolvePepper(); got != "" {
		t.Fatalf("expected empty pepper when neither env var is set, got %q", got)
	}
}

// TestProcessTransaction_BankKeyingEmitsMosaicKeyedBySaltAloneWhenPepperUnset
// drives the real processTransaction handler end to end (the way main()
// actually wires it: resolvePepper's result and cfg.MosaicKeying passed in
// as parameters, not re-read from the environment inside the handler) and
// checks the mosaic it actually emits.
//
// This exists because TestResolvePepper_* only exercises the helper in
// isolation - nothing else drives processTransaction itself and checks the
// emitted mosaic. That gap matters: someone reintroducing
// `pepper := os.Getenv("REGIONAL_PEPPER")` inside the processTransaction
// closure - shadowing the correct, startup-resolved parameter - or hardcoding
// KeyingBank instead of threading cfg.MosaicKeying through, would compile
// cleanly and pass every other test while silently breaking the keying
// contract this PR exists to implement.
func TestProcessTransaction_BankKeyingEmitsMosaicKeyedBySaltAloneWhenPepperUnset(t *testing.T) {
	// processTransaction reads salt/institution_id/mosaic_keying/threshold
	// from the package-level config.Get() singleton (not an injected
	// struct), so the test has to go through the same env-var + Reload()
	// path config_test.go uses.
	bankSalt := "a_sufficiently_long_bank_salt_value"
	t.Setenv("CONFIG_PATH", "/nonexistent/gateway.json")
	t.Setenv("GATEWAY_MODE", "standalone")
	t.Setenv("MOSAIC_KEYING", "") // defaults to bank
	t.Setenv("INSTITUTION_ID", "BANK_A")
	t.Setenv("BANK_SALT", bankSalt)
	t.Setenv("REGIONAL_PEPPER", "") // bank mode: pepper is optional, and normally unset
	t.Setenv("MOSAIC_PEPPER", "")
	t.Cleanup(func() { config.Reload() })

	cfg := config.Reload()
	if cfg.MosaicKeying != config.MosaicKeyingBank {
		t.Fatalf("test setup: expected default MosaicKeying %q, got %q", config.MosaicKeyingBank, cfg.MosaicKeying)
	}

	// Exactly what main() does: resolve the pepper once at startup and pass
	// it (and cfg.MosaicKeying) into processTransaction - never let the
	// handler re-read the env var or hardcode a keying mode.
	pepper := resolvePepper()
	if pepper != "" {
		t.Fatalf("test setup: expected an empty pepper (unset in this scenario), got %q", pepper)
	}

	var captured processor.AnonymizedSignal
	syncForward := func(_ context.Context, signal processor.AnonymizedSignal) error {
		captured = signal
		return nil
	}

	// sp=nil: exercise the synchronous (no SPOOL_DIR) path, which calls
	// syncForward directly - the simplest way to observe exactly what
	// AnonymizeSignal produced inside the real handler.
	handler := processTransaction(nil, syncForward, pepper)

	const nationalID = "22345678901"
	body := `{
		"id": "CUST-001",
		"name": "John Doe",
		"national_id": "` + nationalID + `",
		"account": "ACC-1234567890",
		"amount": 950.00,
		"timestamp": "2026-01-15T14:07:33Z"
	}`
	req := httptest.NewRequest(http.MethodPost, "/process", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if captured.IdentityMosaic == "" {
		t.Fatal("syncForward was never called with a signal")
	}

	normalizedID := processor.NormalizeID(nationalID)
	// Bank keying with an empty pepper folds down to salt alone (see
	// processor.mosaicKeyMaterial), NOT an empty-key HMAC - BANK_SALT is
	// always present.
	wantMosaic := processor.HMACHash(bankSalt, "v3|id|"+normalizedID)
	emptyKeyMosaic := processor.HMACHash("", "v3|id|"+normalizedID)

	if captured.IdentityMosaic != wantMosaic {
		t.Errorf("mosaic not keyed by BANK_SALT alone: got %q, want %q", captured.IdentityMosaic, wantMosaic)
	}
	if captured.IdentityMosaic == emptyKeyMosaic {
		t.Fatal("mosaic matches an EMPTY-KEY HMAC derivation - BANK_SALT was not actually folded into the key")
	}
	if captured.MosaicScope != processor.ScopeBank {
		t.Errorf("expected bank scope for the default keying mode, got %q", captured.MosaicScope)
	}
	if captured.MosaicBasis != processor.BasisNationalID {
		t.Errorf("expected national_id basis, got %q", captured.MosaicBasis)
	}
}

// TestProcessTransaction_RegionalKeyingEmitsMosaicKeyedByPepperAlone is the
// companion to the bank-keying test above: with MOSAIC_KEYING=regional, the
// national-ID mosaic must be keyed on the pepper alone and must NOT depend
// on BANK_SALT at all - proving cfg.MosaicKeying really is threaded through
// processTransaction into AnonymizeSignal, not silently ignored/hardcoded.
func TestProcessTransaction_RegionalKeyingEmitsMosaicKeyedByPepperAlone(t *testing.T) {
	pepperValue := "a_shared_regional_pepper"
	t.Setenv("CONFIG_PATH", "/nonexistent/gateway.json")
	t.Setenv("GATEWAY_MODE", "standalone")
	t.Setenv("MOSAIC_KEYING", "regional")
	t.Setenv("INSTITUTION_ID", "BANK_A")
	t.Setenv("BANK_SALT", "a_sufficiently_long_bank_salt_value")
	t.Setenv("REGIONAL_PEPPER", pepperValue)
	t.Setenv("MOSAIC_PEPPER", "")
	t.Cleanup(func() { config.Reload() })

	cfg := config.Reload()
	if cfg.MosaicKeying != config.MosaicKeyingRegional {
		t.Fatalf("test setup: expected MosaicKeying %q, got %q", config.MosaicKeyingRegional, cfg.MosaicKeying)
	}

	pepper := resolvePepper()
	if pepper != pepperValue {
		t.Fatalf("test setup: expected resolved pepper %q, got %q", pepperValue, pepper)
	}

	var captured processor.AnonymizedSignal
	syncForward := func(_ context.Context, signal processor.AnonymizedSignal) error {
		captured = signal
		return nil
	}
	handler := processTransaction(nil, syncForward, pepper)

	const nationalID = "22345678901"
	body := `{
		"id": "CUST-001",
		"name": "John Doe",
		"national_id": "` + nationalID + `",
		"account": "ACC-1234567890",
		"amount": 950.00,
		"timestamp": "2026-01-15T14:07:33Z"
	}`
	req := httptest.NewRequest(http.MethodPost, "/process", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	normalizedID := processor.NormalizeID(nationalID)
	wantMosaic := processor.HMACHash(pepperValue, "v3|id|"+normalizedID)
	if captured.IdentityMosaic != wantMosaic {
		t.Errorf("mosaic not keyed by the pepper alone: got %q, want %q", captured.IdentityMosaic, wantMosaic)
	}
	if captured.MosaicScope != processor.ScopeRegional {
		t.Errorf("expected regional scope, got %q", captured.MosaicScope)
	}
}

// withFailingSignalID replaces the package-level genSignalID (normally
// processor.NewSignalID) with a func that always fails, for the duration of
// the calling test, and restores it via t.Cleanup. This is how the
// entropy-failure path is exercised end to end through processTransaction
// without needing the OS's real CSPRNG to actually break - see genSignalID's
// doc comment.
func withFailingSignalID(t *testing.T, err error) {
	t.Helper()
	original := genSignalID
	genSignalID = func() (string, error) { return "", err }
	t.Cleanup(func() { genSignalID = original })
}

// withPanicIfCalledSignalID replaces genSignalID with a func that fails the
// test immediately if invoked, so a test can assert that a code path never
// even attempts to generate a fallback signal_id (e.g. because
// transaction_ref was supplied).
func withPanicIfCalledSignalID(t *testing.T) {
	t.Helper()
	original := genSignalID
	genSignalID = func() (string, error) {
		t.Fatal("genSignalID must not be called when transaction_ref is supplied")
		return "", nil
	}
	t.Cleanup(func() { genSignalID = original })
}

// TestProcessTransaction_SignalIDGenerationFailureReturns500Sync is the
// regression test for issue #4: NewSignalID/genSignalID failing (a broken OS
// entropy source) must not panic through to net/http's per-connection
// recover (a bare connection reset, no log line, no metric). It must instead
// be handled exactly like every other failure branch in processTransaction:
// slog.Error with no PII, a distinct metric via adapters.RecordMetric, and a
// proper 500 with a body. Exercises the synchronous (sp == nil) path.
func TestProcessTransaction_SignalIDGenerationFailureReturns500Sync(t *testing.T) {
	t.Setenv("CONFIG_PATH", "/nonexistent/gateway.json")
	t.Setenv("GATEWAY_MODE", "standalone")
	t.Setenv("MOSAIC_KEYING", "")
	t.Setenv("INSTITUTION_ID", "BANK_A")
	t.Setenv("BANK_SALT", "a_sufficiently_long_bank_salt_value")
	t.Setenv("REGIONAL_PEPPER", "")
	t.Setenv("MOSAIC_PEPPER", "")
	t.Cleanup(func() { config.Reload() })
	config.Reload()

	withFailingSignalID(t, errors.New("simulated CSPRNG failure"))

	before := metricValue(t, "signal_id_generation_failures")

	syncForwardCalled := false
	syncForward := func(_ context.Context, _ processor.AnonymizedSignal) error {
		syncForwardCalled = true
		return nil
	}
	handler := processTransaction(nil, syncForward, "")

	// No transaction_ref: this is the only path that needs a generated
	// fallback signal_id, so this is the only path that can observe a
	// crypto/rand failure.
	body := `{
		"id": "CUST-001",
		"name": "John Doe",
		"national_id": "22345678901",
		"account": "ACC-1234567890",
		"amount": 950.00,
		"timestamp": "2026-01-15T14:07:33Z"
	}`
	req := httptest.NewRequest(http.MethodPost, "/process", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d: %s", w.Code, w.Body.String())
	}
	if w.Body.Len() == 0 {
		t.Error("expected a non-empty error body, matching every other failure branch here")
	}
	if syncForwardCalled {
		t.Error("syncForward must not be called when signal_id generation fails - nothing should be delivered")
	}
	if got := metricValue(t, "signal_id_generation_failures"); got != before+1 {
		t.Errorf("expected signal_id_generation_failures to increment by 1, got %d -> %d", before, got)
	}
}

// TestProcessTransaction_SignalIDGenerationFailureReturns500Async is the
// spool-mode (sp != nil) companion to the sync test above - CLAUDE.md notes
// "Both modes must stay in sync when changing response shape or metrics",
// so both need direct coverage of this failure path.
func TestProcessTransaction_SignalIDGenerationFailureReturns500Async(t *testing.T) {
	t.Setenv("CONFIG_PATH", "/nonexistent/gateway.json")
	t.Setenv("GATEWAY_MODE", "standalone")
	t.Setenv("MOSAIC_KEYING", "")
	t.Setenv("INSTITUTION_ID", "BANK_A")
	t.Setenv("BANK_SALT", "a_sufficiently_long_bank_salt_value")
	t.Setenv("REGIONAL_PEPPER", "")
	t.Setenv("MOSAIC_PEPPER", "")
	t.Cleanup(func() { config.Reload() })
	config.Reload()

	withFailingSignalID(t, errors.New("simulated CSPRNG failure"))

	before := metricValue(t, "signal_id_generation_failures")

	sp, err := spool.New(t.TempDir(), 10, func(context.Context, []byte) error { return nil }, func(error) bool { return false }, spool.Hooks{})
	if err != nil {
		t.Fatalf("spool.New: %v", err)
	}

	handler := processTransaction(sp, func(context.Context, processor.AnonymizedSignal) error { return nil }, "")

	body := `{
		"id": "CUST-001",
		"name": "John Doe",
		"national_id": "22345678901",
		"account": "ACC-1234567890",
		"amount": 950.00,
		"timestamp": "2026-01-15T14:07:33Z"
	}`
	req := httptest.NewRequest(http.MethodPost, "/process", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d: %s", w.Code, w.Body.String())
	}
	if sp.Depth() != 0 {
		t.Errorf("expected nothing enqueued when signal_id generation fails, spool depth = %d", sp.Depth())
	}
	if got := metricValue(t, "signal_id_generation_failures"); got != before+1 {
		t.Errorf("expected signal_id_generation_failures to increment by 1, got %d -> %d", before, got)
	}
}

// TestProcessTransaction_TransactionRefSuppliedSkipsSignalIDGeneration
// confirms genSignalID is only invoked when it's actually needed: a request
// with transaction_ref set derives signal_id deterministically and must
// never touch OS entropy at all.
func TestProcessTransaction_TransactionRefSuppliedSkipsSignalIDGeneration(t *testing.T) {
	t.Setenv("CONFIG_PATH", "/nonexistent/gateway.json")
	t.Setenv("GATEWAY_MODE", "standalone")
	t.Setenv("MOSAIC_KEYING", "")
	t.Setenv("INSTITUTION_ID", "BANK_A")
	t.Setenv("BANK_SALT", "a_sufficiently_long_bank_salt_value")
	t.Setenv("REGIONAL_PEPPER", "")
	t.Setenv("MOSAIC_PEPPER", "")
	t.Cleanup(func() { config.Reload() })
	config.Reload()

	withPanicIfCalledSignalID(t)

	var captured processor.AnonymizedSignal
	syncForward := func(_ context.Context, signal processor.AnonymizedSignal) error {
		captured = signal
		return nil
	}
	handler := processTransaction(nil, syncForward, "")

	body := `{
		"id": "CUST-001",
		"name": "John Doe",
		"national_id": "22345678901",
		"account": "ACC-1234567890",
		"amount": 950.00,
		"timestamp": "2026-01-15T14:07:33Z",
		"transaction_ref": "core-banking-ref-1"
	}`
	req := httptest.NewRequest(http.MethodPost, "/process", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if captured.SignalID == "" {
		t.Fatal("expected a derived signal_id")
	}
}

// TestProcessTransaction_WhitespaceOnlyTransactionRefTreatedAsAbsent is the
// end-to-end regression test for processor.NeedsFallbackSignalID: before
// that shared predicate existed, "is transaction_ref absent" was checked
// independently in processTransaction (deciding whether to call
// genSignalID) and in AnonymizeSignal (deciding which signal_id branch to
// take). They happened to agree, but nothing forced it, and no test drove a
// whitespace-only transaction_ref through processTransaction end to end to
// prove it - exactly the gap where a drift between the two copies would
// have gone undetected (see NeedsFallbackSignalID's doc comment).
//
// The decisive check is sending the SAME whitespace-only ref twice and
// requiring two DIFFERENT signal_id values: a ref-derived signal_id is
// deterministic (same ref + same salt -> same hash every time, as the
// determinism tests in internal/processor/anonymizer_test.go establish),
// so two different results is only possible if genSignalID actually fired
// both times and its output actually reached the response - i.e. the
// whole pipeline agreed the ref was absent, not just one half of it. A
// weaker assertion (just "non-empty", or comparing against one specific
// wrong-derivation formula) would pass under several drifted-predicate
// mutations that still happen to produce a non-empty, non-sentinel value;
// this one does not.
func TestProcessTransaction_WhitespaceOnlyTransactionRefTreatedAsAbsent(t *testing.T) {
	t.Setenv("CONFIG_PATH", "/nonexistent/gateway.json")
	t.Setenv("GATEWAY_MODE", "standalone")
	t.Setenv("MOSAIC_KEYING", "")
	t.Setenv("INSTITUTION_ID", "BANK_A")
	t.Setenv("BANK_SALT", "a_sufficiently_long_bank_salt_value")
	t.Setenv("REGIONAL_PEPPER", "")
	t.Setenv("MOSAIC_PEPPER", "")
	t.Cleanup(func() { config.Reload() })
	config.Reload()

	const whitespaceRef = "   "
	body := `{
		"id": "CUST-001",
		"name": "John Doe",
		"national_id": "22345678901",
		"account": "ACC-1234567890",
		"amount": 950.00,
		"timestamp": "2026-01-15T14:07:33Z",
		"transaction_ref": "` + whitespaceRef + `"
	}`

	post := func() (int, processor.AnonymizedSignal, map[string]interface{}) {
		var captured processor.AnonymizedSignal
		syncForward := func(_ context.Context, signal processor.AnonymizedSignal) error {
			captured = signal
			return nil
		}
		handler := processTransaction(nil, syncForward, "")

		req := httptest.NewRequest(http.MethodPost, "/process", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		handler(w, req)

		var resp map[string]interface{}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode response body: %v", err)
		}
		return w.Code, captured, resp
	}

	code1, sig1, resp1 := post()
	code2, sig2, resp2 := post()

	if code1 != http.StatusOK {
		t.Fatalf("first request: expected 200, got %d", code1)
	}
	if code2 != http.StatusOK {
		t.Fatalf("second request: expected 200, got %d", code2)
	}

	for _, sig := range []processor.AnonymizedSignal{sig1, sig2} {
		if sig.SignalID == "" {
			t.Fatal("expected a non-empty, generated signal_id for a whitespace-only transaction_ref")
		}
		if sig.SignalID == processor.MissingSignalIDSentinel {
			t.Fatalf("signal_id fell back to the missing-fallback sentinel %q - genSignalID was not invoked for a whitespace-only ref", sig.SignalID)
		}
		if sig.SignalID == whitespaceRef {
			t.Error("signal_id must never equal the raw (whitespace) transaction_ref")
		}
	}

	// The decisive assertion: identical requests, but each must get its own
	// freshly generated fallback id.
	if sig1.SignalID == sig2.SignalID {
		t.Fatalf("two requests with the same whitespace-only transaction_ref got the SAME signal_id (%q) - this means signal_id is being deterministically derived from the ref instead of coming from a freshly generated fallback, i.e. transaction_ref is NOT being treated as absent end to end", sig1.SignalID)
	}

	if id, _ := resp1["signal_id"].(string); id != sig1.SignalID {
		t.Errorf("expected the first HTTP response signal_id to match the generated fallback %q, got %q", sig1.SignalID, id)
	}
	if id, _ := resp2["signal_id"].(string); id != sig2.SignalID {
		t.Errorf("expected the second HTTP response signal_id to match the generated fallback %q, got %q", sig2.SignalID, id)
	}
}

func TestValidateStartup_UnknownModeRejected(t *testing.T) {
	cfg := &config.GatewayConfig{
		Mode:         "bogus",
		MosaicKeying: config.MosaicKeyingBank,
		Hub: config.HubParams{
			InstitutionID: "BANK_A",
		},
		Local: config.LocalParams{
			BankSalt: "a_sufficiently_long_bank_salt_value",
		},
	}

	problems := validateStartup(cfg)
	if len(problems) != 1 {
		t.Fatalf("expected exactly 1 problem (unknown mode), got %d: %v", len(problems), problems)
	}
}
