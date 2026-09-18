package config

import (
	"os"
	"path/filepath"
	"testing"
)

func writeConfigFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "gateway.json")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoad_EnvOverridesFile(t *testing.T) {
	path := writeConfigFile(t, `{
		"hub": {"institution_id": "FILE_INST", "api_key": "file_key", "hub_endpoint_url": "http://file/signals"},
		"local": {"bank_salt": "file_salt", "reporting_threshold": 5000}
	}`)
	t.Setenv("CONFIG_PATH", path)
	t.Setenv("INSTITUTION_ID", "ENV_INST")
	t.Setenv("API_KEY", "")
	t.Setenv("HUB_API_URL", "")
	t.Setenv("BANK_SALT", "")
	t.Setenv("REPORTING_THRESHOLD", "20000")
	t.Cleanup(func() { Reload() })

	cfg := Reload()

	if cfg.Hub.InstitutionID != "ENV_INST" {
		t.Errorf("env must override file: got %q", cfg.Hub.InstitutionID)
	}
	if cfg.Hub.APIKey != "file_key" {
		t.Errorf("file should provide default when env unset: got %q", cfg.Hub.APIKey)
	}
	if cfg.Local.BankSalt != "file_salt" {
		t.Errorf("file salt should apply when env unset: got %q", cfg.Local.BankSalt)
	}
	if cfg.Local.ReportingThreshold != 20000 {
		t.Errorf("env threshold must override file: got %v", cfg.Local.ReportingThreshold)
	}
}

func TestLoad_DefaultsWithoutFile(t *testing.T) {
	t.Setenv("CONFIG_PATH", "/nonexistent/gateway.json")
	t.Setenv("INSTITUTION_ID", "ENV_INST")
	t.Setenv("API_KEY", "env_key")
	t.Setenv("HUB_API_URL", "")
	t.Setenv("BANK_SALT", "env_salt")
	t.Setenv("REPORTING_THRESHOLD", "")
	t.Setenv("LOCAL_LOG_RETENTION_DAYS", "")
	t.Cleanup(func() { Reload() })

	cfg := Reload()

	// HubEndpointURL must NOT get a built-in placeholder default: that would
	// make the "is a destination configured?" startup check in main.go
	// unreachable dead code, and a middleware gateway with no real
	// destination would start happily and POST to a fake host.
	if cfg.Hub.HubEndpointURL != "" {
		t.Errorf("expected no built-in hub URL default, got %q", cfg.Hub.HubEndpointURL)
	}
	if cfg.Local.ReportingThreshold != 10000 {
		t.Errorf("expected default threshold 10000, got %v", cfg.Local.ReportingThreshold)
	}
	if cfg.Local.LocalLogRetentionDays != 90 {
		t.Errorf("expected default retention 90, got %v", cfg.Local.LocalLogRetentionDays)
	}
}

func TestLoad_ModeDefaultsToMiddleware(t *testing.T) {
	t.Setenv("CONFIG_PATH", "/nonexistent/gateway.json")
	t.Setenv("GATEWAY_MODE", "")
	t.Cleanup(func() { Reload() })

	cfg := Reload()

	if cfg.Mode != ModeMiddleware {
		t.Errorf("expected default mode %q, got %q", ModeMiddleware, cfg.Mode)
	}
	if cfg.IsStandalone() {
		t.Errorf("middleware mode must not report IsStandalone()")
	}
}

func TestLoad_ModeFromEnv_NormalizedCaseAndWhitespace(t *testing.T) {
	t.Setenv("CONFIG_PATH", "/nonexistent/gateway.json")
	t.Setenv("GATEWAY_MODE", "  Standalone  ")
	t.Cleanup(func() { Reload() })

	cfg := Reload()

	if cfg.Mode != ModeStandalone {
		t.Errorf("expected normalized mode %q, got %q", ModeStandalone, cfg.Mode)
	}
	if !cfg.IsStandalone() {
		t.Errorf("expected IsStandalone() true for standalone mode")
	}
}

func TestLoad_ModeEnvOverridesFile(t *testing.T) {
	path := writeConfigFile(t, `{"mode": "standalone"}`)
	t.Setenv("CONFIG_PATH", path)
	t.Setenv("GATEWAY_MODE", "middleware")
	t.Cleanup(func() { Reload() })

	cfg := Reload()

	if cfg.Mode != ModeMiddleware {
		t.Errorf("env must override file mode: got %q", cfg.Mode)
	}
}

func TestLoad_ModeFromFile(t *testing.T) {
	path := writeConfigFile(t, `{"mode": "standalone"}`)
	t.Setenv("CONFIG_PATH", path)
	t.Setenv("GATEWAY_MODE", "")
	t.Cleanup(func() { Reload() })

	cfg := Reload()

	if cfg.Mode != ModeStandalone {
		t.Errorf("expected mode from file %q, got %q", ModeStandalone, cfg.Mode)
	}
}

func TestLoad_MosaicKeyingDefaultsToBank(t *testing.T) {
	t.Setenv("CONFIG_PATH", "/nonexistent/gateway.json")
	t.Setenv("MOSAIC_KEYING", "")
	t.Cleanup(func() { Reload() })

	cfg := Reload()

	if cfg.MosaicKeying != MosaicKeyingBank {
		t.Errorf("expected default mosaic keying %q, got %q", MosaicKeyingBank, cfg.MosaicKeying)
	}
}

func TestLoad_MosaicKeyingFromEnv_NormalizedCaseAndWhitespace(t *testing.T) {
	t.Setenv("CONFIG_PATH", "/nonexistent/gateway.json")
	t.Setenv("MOSAIC_KEYING", "  Regional  ")
	t.Cleanup(func() { Reload() })

	cfg := Reload()

	if cfg.MosaicKeying != MosaicKeyingRegional {
		t.Errorf("expected normalized mosaic keying %q, got %q", MosaicKeyingRegional, cfg.MosaicKeying)
	}
}

func TestLoad_MosaicKeyingEnvOverridesFile(t *testing.T) {
	path := writeConfigFile(t, `{"mosaic_keying": "regional"}`)
	t.Setenv("CONFIG_PATH", path)
	t.Setenv("MOSAIC_KEYING", "bank")
	t.Cleanup(func() { Reload() })

	cfg := Reload()

	if cfg.MosaicKeying != MosaicKeyingBank {
		t.Errorf("env must override file mosaic keying: got %q", cfg.MosaicKeying)
	}
}

func TestLoad_MosaicKeyingFromFile(t *testing.T) {
	path := writeConfigFile(t, `{"mosaic_keying": "regional"}`)
	t.Setenv("CONFIG_PATH", path)
	t.Setenv("MOSAIC_KEYING", "")
	t.Cleanup(func() { Reload() })

	cfg := Reload()

	if cfg.MosaicKeying != MosaicKeyingRegional {
		t.Errorf("expected mosaic keying from file %q, got %q", MosaicKeyingRegional, cfg.MosaicKeying)
	}
}
