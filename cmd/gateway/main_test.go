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
	t.Setenv("HUB_API_URL", "")
	t.Setenv("HMAC_SECRET", "")

	cfg := &config.GatewayConfig{
		Mode: config.ModeStandalone,
		Hub: config.HubParams{
			InstitutionID: "BANK_A",
			// APIKey and HubEndpointURL deliberately left empty.
		},
		Local: config.LocalParams{
			BankSalt: "a_sufficiently_long_bank_salt_value",
		},
	}

	if problems := validateStartup(cfg); len(problems) != 0 {
		t.Fatalf("expected standalone mode to start without REGIONAL_PEPPER/HUB_API_URL, got problems: %v", problems)
	}
}

func TestValidateStartup_StandaloneStillRequiresInstitutionAndSalt(t *testing.T) {
	cfg := &config.GatewayConfig{Mode: config.ModeStandalone}

	problems := validateStartup(cfg)
	if len(problems) != 2 {
		t.Fatalf("expected 2 problems (institution_id, bank_salt), got %d: %v", len(problems), problems)
	}
}

func TestValidateStartup_MiddlewareFailsFastWithoutDestination(t *testing.T) {
	t.Setenv("HMAC_SECRET", "some_secret")
	t.Setenv("REGIONAL_PEPPER", "some_pepper")

	cfg := &config.GatewayConfig{
		Mode: config.ModeMiddleware,
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

func TestValidateStartup_MiddlewareRequiresPepperAndHmacSecret(t *testing.T) {
	t.Setenv("HMAC_SECRET", "")
	t.Setenv("REGIONAL_PEPPER", "")

	cfg := &config.GatewayConfig{
		Mode: config.ModeMiddleware,
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
	if len(problems) != 2 {
		t.Fatalf("expected 2 problems (HMAC_SECRET, REGIONAL_PEPPER), got %d: %v", len(problems), problems)
	}
}

func TestValidateStartup_MiddlewareFullyConfiguredStartsClean(t *testing.T) {
	t.Setenv("HMAC_SECRET", "some_secret")
	t.Setenv("REGIONAL_PEPPER", "some_pepper")

	cfg := &config.GatewayConfig{
		Mode: config.ModeMiddleware,
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
		t.Fatalf("expected fully-configured middleware mode to start clean, got problems: %v", problems)
	}
}

func TestResolvePepper_StandaloneWithoutRegionalPepperDerivesFromBankSalt(t *testing.T) {
	t.Setenv("REGIONAL_PEPPER", "")

	bankSalt := "a_sufficiently_long_bank_salt_value"
	cfg := &config.GatewayConfig{
		Mode:  config.ModeStandalone,
		Local: config.LocalParams{BankSalt: bankSalt},
	}

	pepper, derived := resolvePepper(cfg)

	if !derived {
		t.Fatal("expected resolvePepper to report the pepper as derived")
	}
	if pepper == "" {
		t.Fatal("standalone mode must never derive an empty pepper - HMAC with an empty key is a publicly computable function")
	}
	if pepper == bankSalt {
		t.Fatal("derived pepper must not equal BANK_SALT verbatim (must be a distinct derivation, not a passthrough)")
	}
}

func TestResolvePepper_StandaloneWithExplicitRegionalPepperUsesItAsIs(t *testing.T) {
	t.Setenv("REGIONAL_PEPPER", "an_explicit_pepper")

	cfg := &config.GatewayConfig{
		Mode:  config.ModeStandalone,
		Local: config.LocalParams{BankSalt: "a_sufficiently_long_bank_salt_value"},
	}

	pepper, derived := resolvePepper(cfg)

	if derived {
		t.Fatal("expected resolvePepper to use the explicit REGIONAL_PEPPER, not derive one")
	}
	if pepper != "an_explicit_pepper" {
		t.Fatalf("expected explicit pepper to pass through unchanged, got %q", pepper)
	}
}

func TestResolvePepper_MiddlewareUsesRegionalPepperAsIs(t *testing.T) {
	t.Setenv("REGIONAL_PEPPER", "the_shared_pepper")

	cfg := &config.GatewayConfig{
		Mode:  config.ModeMiddleware,
		Local: config.LocalParams{BankSalt: "a_sufficiently_long_bank_salt_value"},
	}

	pepper, derived := resolvePepper(cfg)

	if derived {
		t.Fatal("middleware mode must never derive a pepper")
	}
	if pepper != "the_shared_pepper" {
		t.Fatalf("expected REGIONAL_PEPPER value unchanged, got %q", pepper)
	}
}

// TestProcessTransaction_StandaloneEmitsMosaicKeyedByDerivedPepper drives the
// real processTransaction handler end to end (the way main() actually wires
// it: resolvePepper's result passed in as a parameter, not re-read from the
// environment inside the handler) and checks the mosaic it actually emits.
//
// This exists because TestResolvePepper_* only exercises the helper in
// isolation, and sink_test.go only exercises localSink in isolation -
// nothing previously drove processTransaction itself and checked the
// emitted mosaic. That gap matters: someone reintroducing
// `pepper := os.Getenv("REGIONAL_PEPPER")` inside the processTransaction
// closure - shadowing the correct, startup-resolved parameter - would
// compile cleanly and pass every other test, while silently resurrecting
// the exact empty-key-HMAC defect this PR exists to fix (REGIONAL_PEPPER is
// unset in standalone mode, so os.Getenv would return ""). This test fails
// in that scenario because it asserts the emitted mosaic matches the
// DERIVED pepper and explicitly does not match what an empty-key HMAC would
// produce.
func TestProcessTransaction_StandaloneEmitsMosaicKeyedByDerivedPepper(t *testing.T) {
	// processTransaction reads salt/institution_id/threshold from the
	// package-level config.Get() singleton (not an injected struct), so the
	// test has to go through the same env-var + Reload() path config_test.go
	// uses, and use the *same* cfg for resolvePepper, for the two to agree.
	bankSalt := "a_sufficiently_long_bank_salt_value"
	t.Setenv("CONFIG_PATH", "/nonexistent/gateway.json")
	t.Setenv("GATEWAY_MODE", "standalone")
	t.Setenv("INSTITUTION_ID", "BANK_A")
	t.Setenv("BANK_SALT", bankSalt)
	t.Setenv("REGIONAL_PEPPER", "") // standalone mode: unset, as in normal use
	t.Cleanup(func() { config.Reload() })

	cfg := config.Reload()

	// Exactly what main() does: resolve the pepper once at startup and pass
	// it into processTransaction - never let the handler re-read the env var.
	pepper, derived := resolvePepper(cfg)
	if !derived || pepper == "" {
		t.Fatalf("test setup: expected a non-empty derived pepper, got %q (derived=%v)", pepper, derived)
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
	wantMosaic := processor.HMACHash(pepper, "v2|id|"+normalizedID)
	emptyKeyMosaic := processor.HMACHash("", "v2|id|"+normalizedID)

	if captured.IdentityMosaic != wantMosaic {
		t.Errorf("mosaic not keyed by the resolved (derived) pepper: got %q, want %q", captured.IdentityMosaic, wantMosaic)
	}
	if captured.IdentityMosaic == emptyKeyMosaic {
		t.Fatal("mosaic matches an EMPTY-KEY HMAC derivation - the pepper resolved at startup was not the one actually used; this is the blocking defect the PR fixed")
	}
	if captured.MosaicScope != "global" {
		t.Errorf("expected global scope for a signal with national_id, got %q", captured.MosaicScope)
	}
}

func TestValidateStartup_UnknownModeRejected(t *testing.T) {
	cfg := &config.GatewayConfig{
		Mode: "bogus",
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
