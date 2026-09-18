package main

import (
	"testing"

	"github.com/papoveB01/EdgeGW_Project/internal/config"
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
