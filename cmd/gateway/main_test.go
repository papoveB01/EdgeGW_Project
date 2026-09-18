package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/papoveB01/EdgeGW_Project/internal/config"
	"github.com/papoveB01/EdgeGW_Project/internal/processor"
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
