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

	if cfg.Hub.HubEndpointURL != "http://intel-api:8000/api/v1/signals" {
		t.Errorf("expected built-in hub URL default, got %q", cfg.Hub.HubEndpointURL)
	}
	if cfg.Local.ReportingThreshold != 10000 {
		t.Errorf("expected default threshold 10000, got %v", cfg.Local.ReportingThreshold)
	}
	if cfg.Local.LocalLogRetentionDays != 90 {
		t.Errorf("expected default retention 90, got %v", cfg.Local.LocalLogRetentionDays)
	}
}
