package config

import (
	"encoding/json"
	"log/slog"
	"os"
	"strconv"
	"sync"
)

// HubParams are provided by the Hub UI and identify the gateway to the Hub.
type HubParams struct {
	InstitutionID  string `json:"institution_id"`
	APIKey         string `json:"api_key"`
	HubEndpointURL string `json:"hub_endpoint_url"`
}

// InternalAdapterConfig maps the bank's internal ATM/POS ports or identifiers.
type InternalAdapterConfig map[string]interface{}

// LocalParams are managed locally by the bank (not sent to Hub).
type LocalParams struct {
	BankSalt              string                `json:"bank_salt"`
	InternalAdapterConfig InternalAdapterConfig `json:"internal_adapter_config"`
	LocalLogRetentionDays int                   `json:"local_log_retention"`
	ReportingThreshold    float64               `json:"reporting_threshold"`
}

// GatewayConfig combines Hub and local configuration.
type GatewayConfig struct {
	Hub   HubParams   `json:"hub"`
	Local LocalParams `json:"local"`
}

var (
	mu     sync.Mutex
	cached *GatewayConfig
)

// Load reads configuration. The config file (CONFIG_PATH) provides defaults;
// environment variables take precedence over file values.
func Load() *GatewayConfig {
	mu.Lock()
	defer mu.Unlock()
	if cached != nil {
		return cached
	}
	cfg := &GatewayConfig{
		Local: LocalParams{
			InternalAdapterConfig: make(InternalAdapterConfig),
		},
	}

	// 1. File provides defaults.
	configPath := os.Getenv("CONFIG_PATH")
	if configPath == "" {
		configPath = "/config/gateway.json"
	}
	if f, err := os.Open(configPath); err == nil {
		fileCfg := &GatewayConfig{}
		if err := json.NewDecoder(f).Decode(fileCfg); err == nil {
			cfg.Hub = fileCfg.Hub
			cfg.Local.BankSalt = fileCfg.Local.BankSalt
			if len(fileCfg.Local.InternalAdapterConfig) > 0 {
				cfg.Local.InternalAdapterConfig = fileCfg.Local.InternalAdapterConfig
			}
			cfg.Local.LocalLogRetentionDays = fileCfg.Local.LocalLogRetentionDays
			cfg.Local.ReportingThreshold = fileCfg.Local.ReportingThreshold
			slog.Info("Loaded config defaults from file", "path", configPath)
		} else {
			slog.Warn("Failed to parse config file, ignoring", "path", configPath, "error", err)
		}
		f.Close()
	}

	// 2. Environment variables override file values.
	if v := os.Getenv("INSTITUTION_ID"); v != "" {
		cfg.Hub.InstitutionID = v
	}
	if v := os.Getenv("API_KEY"); v != "" {
		cfg.Hub.APIKey = v
	}
	if v := os.Getenv("HUB_API_URL"); v != "" {
		cfg.Hub.HubEndpointURL = v
	}
	if v := os.Getenv("BANK_SALT"); v != "" {
		cfg.Local.BankSalt = v
	}
	if s := os.Getenv("INTERNAL_ADAPTER_CONFIG"); s != "" {
		_ = json.Unmarshal([]byte(s), &cfg.Local.InternalAdapterConfig)
	}
	if v, ok := envInt("LOCAL_LOG_RETENTION_DAYS"); ok {
		cfg.Local.LocalLogRetentionDays = v
	}
	if v, ok := envFloat("REPORTING_THRESHOLD"); ok {
		cfg.Local.ReportingThreshold = v
	}

	// 3. Built-in defaults for anything still unset.
	if cfg.Hub.HubEndpointURL == "" {
		cfg.Hub.HubEndpointURL = "http://intel-api:8000/api/v1/signals"
	}
	if cfg.Local.LocalLogRetentionDays <= 0 {
		cfg.Local.LocalLogRetentionDays = 90
	}
	if cfg.Local.ReportingThreshold <= 0 {
		cfg.Local.ReportingThreshold = 10000
	}

	cached = cfg
	return cfg
}

// Reload forces a config reload from environment and file. Call on SIGHUP.
func Reload() *GatewayConfig {
	mu.Lock()
	cached = nil
	mu.Unlock()
	return Load()
}

func envInt(key string) (int, bool) {
	s := os.Getenv(key)
	if s == "" {
		return 0, false
	}
	v, err := strconv.Atoi(s)
	if err != nil {
		return 0, false
	}
	return v, true
}

func envFloat(key string) (float64, bool) {
	s := os.Getenv(key)
	if s == "" {
		return 0, false
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

// Get returns the current gateway config (loads if needed).
func Get() *GatewayConfig {
	return Load()
}
