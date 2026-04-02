package config

import (
	"encoding/json"
	"log/slog"
	"os"
	"strconv"
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

var cached *GatewayConfig

// Load reads configuration from environment, then optionally from CONFIG_PATH file.
func Load() *GatewayConfig {
	if cached != nil {
		return cached
	}
	cfg := &GatewayConfig{
		Hub: HubParams{
			InstitutionID:  os.Getenv("INSTITUTION_ID"),
			APIKey:         os.Getenv("API_KEY"),
			HubEndpointURL: os.Getenv("HUB_API_URL"),
		},
		Local: LocalParams{
			BankSalt:              os.Getenv("BANK_SALT"),
			InternalAdapterConfig: make(InternalAdapterConfig),
			LocalLogRetentionDays: envInt("LOCAL_LOG_RETENTION_DAYS", 90),
			ReportingThreshold:    envFloat("REPORTING_THRESHOLD", 10000),
		},
	}
	if cfg.Hub.HubEndpointURL == "" {
		cfg.Hub.HubEndpointURL = "http://intel-api:8000/api/v1/signals"
	}
	if s := os.Getenv("INTERNAL_ADAPTER_CONFIG"); s != "" {
		_ = json.Unmarshal([]byte(s), &cfg.Local.InternalAdapterConfig)
	}

	configPath := os.Getenv("CONFIG_PATH")
	if configPath == "" {
		configPath = "/config/gateway.json"
	}
	f, err := os.Open(configPath)
	if err == nil {
		defer f.Close()
		fileCfg := &GatewayConfig{}
		if err := json.NewDecoder(f).Decode(fileCfg); err == nil {
			if fileCfg.Hub.InstitutionID != "" {
				cfg.Hub.InstitutionID = fileCfg.Hub.InstitutionID
			}
			if fileCfg.Hub.APIKey != "" {
				cfg.Hub.APIKey = fileCfg.Hub.APIKey
			}
			if fileCfg.Hub.HubEndpointURL != "" {
				cfg.Hub.HubEndpointURL = fileCfg.Hub.HubEndpointURL
			}
			if fileCfg.Local.BankSalt != "" {
				cfg.Local.BankSalt = fileCfg.Local.BankSalt
			}
			if len(fileCfg.Local.InternalAdapterConfig) > 0 {
				cfg.Local.InternalAdapterConfig = fileCfg.Local.InternalAdapterConfig
			}
			if fileCfg.Local.LocalLogRetentionDays > 0 {
				cfg.Local.LocalLogRetentionDays = fileCfg.Local.LocalLogRetentionDays
			}
			if fileCfg.Local.ReportingThreshold > 0 {
				cfg.Local.ReportingThreshold = fileCfg.Local.ReportingThreshold
			}
			slog.Info("Loaded config overrides from file", "path", configPath)
		}
	}
	cached = cfg
	return cfg
}

// Reload forces a config reload from environment and file. Call on SIGHUP.
func Reload() *GatewayConfig {
	cached = nil
	return Load()
}

func envInt(key string, defaultVal int) int {
	s := os.Getenv(key)
	if s == "" {
		return defaultVal
	}
	v, err := strconv.Atoi(s)
	if err != nil {
		return defaultVal
	}
	return v
}

func envFloat(key string, defaultVal float64) float64 {
	s := os.Getenv(key)
	if s == "" {
		return defaultVal
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return defaultVal
	}
	return v
}

// Get returns the current gateway config (loads if needed).
func Get() *GatewayConfig {
	if cached == nil {
		return Load()
	}
	return cached
}
