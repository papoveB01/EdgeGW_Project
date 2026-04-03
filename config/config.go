package config

import (
	"encoding/json"
	"log"
	"os"
	"strconv"
	"sync"
)

// HubParams are provided by the Hub UI (or config export) and identify the gateway to the Hub.
type HubParams struct {
	InstitutionID  string `json:"institution_id"`   // e.g. BNK_001
	APIKey         string `json:"api_key"`           // Bearer token for Hub auth
	HubEndpointURL string `json:"hub_endpoint_url"` // Where to send anonymized signals
}

// InternalAdapterConfig maps the bank's internal ATM/POS ports or identifiers.
// Example: {"atm": {"port": 9001}, "pos": {"port": 9002}}
type InternalAdapterConfig map[string]interface{}

// LocalParams are managed locally by the bank (not sent to Hub).
type LocalParams struct {
	BankSalt              string                `json:"bank_salt"`               // Privacy key for anonymization
	InternalAdapterConfig InternalAdapterConfig `json:"internal_adapter_config"` // ATM/POS port mapping
	LocalLogRetentionDays int                   `json:"local_log_retention"`     // How long to keep audit trails (days)
	ReportingThreshold    float64               `json:"reporting_threshold"`     // AML reporting limit (e.g. 10000); used for is_near_threshold (Multi-Bank Structuring)
}

// GatewayConfig combines Hub and local configuration.
// Can be loaded from environment and optionally overridden by a JSON file.
type GatewayConfig struct {
	Hub   HubParams   `json:"hub"`
	Local LocalParams `json:"local"`
}

var (
	cached *GatewayConfig
	once   sync.Once
	mu     sync.RWMutex
)

// Load reads configuration from environment, then optionally from CONFIG_PATH file.
// Env vars (Hub): INSTITUTION_ID, API_KEY, HUB_API_URL (or hub_endpoint_url in file).
// Env vars (Local): BANK_SALT, INTERNAL_ADAPTER_CONFIG (JSON string), LOCAL_LOG_RETENTION_DAYS.
func Load() *GatewayConfig {
	once.Do(func() {
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
			dec := json.NewDecoder(f)
			fileCfg := &GatewayConfig{}
			if err := dec.Decode(fileCfg); err == nil {
				if fileCfg.Hub.InstitutionID != "" {
					cfg.Hub.InstitutionID = fileCfg.Hub.InstitutionID
				}
				if fileCfg.Hub.APIKey != "" {
					log.Print("WARNING: api_key loaded from config file — prefer setting API_KEY via environment variable for security")
					cfg.Hub.APIKey = fileCfg.Hub.APIKey
				}
				if fileCfg.Hub.HubEndpointURL != "" {
					cfg.Hub.HubEndpointURL = fileCfg.Hub.HubEndpointURL
				}
				if fileCfg.Local.BankSalt != "" {
					log.Print("WARNING: bank_salt loaded from config file — prefer setting BANK_SALT via environment variable for security")
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
				log.Printf("Loaded config overrides from %s", configPath)
			}
		}
		cached = cfg
	})
	return cached
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
	return Load()
}

// ResetForTest clears the cached config so Load() runs again.
// Only use this in tests.
func ResetForTest() {
	mu.Lock()
	defer mu.Unlock()
	cached = nil
	once = sync.Once{}
}
