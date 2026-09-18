package config

import (
	"encoding/json"
	"log/slog"
	"os"
	"strconv"
	"strings"
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
	// Mode selects the deployment topology: ModeMiddleware (default, current
	// behavior) forwards anonymized signals to an external vendor platform;
	// ModeStandalone runs with no external system and requires none of the
	// Hub/vendor credentials.
	Mode string `json:"mode"`
	// MosaicKeying selects how internal/processor.AnonymizeSignal keys
	// identity/destination mosaics: MosaicKeyingBank (default) folds this
	// institution's BANK_SALT into every mosaic; MosaicKeyingRegional
	// (opt-in) keys national-ID-derived mosaics on the shared pepper alone,
	// preserving cross-gateway derivability for a future regional querying
	// use case. See processor.KeyingBank/KeyingRegional for the derivation
	// details and processor.ScopeBank/ScopeRegional for what it means on the
	// wire.
	MosaicKeying string      `json:"mosaic_keying"`
	Hub          HubParams   `json:"hub"`
	Local        LocalParams `json:"local"`
}

const (
	// ModeMiddleware forwards signals one-way to an external vendor fraud
	// platform for inference only. This is the default, matching historical
	// behavior of this gateway.
	ModeMiddleware = "middleware"
	// ModeStandalone runs the gateway independent of any external system;
	// signals are written to a local durable sink instead of forwarded.
	ModeStandalone = "standalone"
)

const (
	// MosaicKeyingBank is the default MosaicKeying value: every mosaic folds
	// in this institution's own BANK_SALT, so it is not reproducible by
	// anyone lacking that secret. The pepper (MOSAIC_PEPPER/REGIONAL_PEPPER)
	// is optional in this mode.
	MosaicKeyingBank = "bank"
	// MosaicKeyingRegional is the opt-in MosaicKeying value: mosaics derived
	// from a canonical national ID are keyed on the shared pepper alone,
	// exactly like the pre-v3 scheme, so every gateway sharing that pepper
	// derives the same mosaic for the same person. The pepper is REQUIRED in
	// this mode — main.validateStartup fails fast at startup if it is unset.
	MosaicKeyingRegional = "regional"
)

// IsStandalone reports whether the gateway is configured to run without any
// external destination.
func (c *GatewayConfig) IsStandalone() bool {
	return c.Mode == ModeStandalone
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
			cfg.Mode = fileCfg.Mode
			cfg.MosaicKeying = fileCfg.MosaicKeying
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
	if v := os.Getenv("GATEWAY_MODE"); v != "" {
		cfg.Mode = v
	}
	if v := os.Getenv("MOSAIC_KEYING"); v != "" {
		cfg.MosaicKeying = v
	}
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
	//
	// HubEndpointURL deliberately has NO built-in default: a placeholder here
	// would make the "is a destination configured?" check in main.go
	// unreachable dead code (a gateway with no real destination would start
	// happily and POST to a fake host). Middleware mode requires it to be set
	// explicitly; standalone mode doesn't need it at all.
	cfg.Mode = strings.ToLower(strings.TrimSpace(cfg.Mode))
	if cfg.Mode == "" {
		cfg.Mode = ModeMiddleware
	}
	cfg.MosaicKeying = strings.ToLower(strings.TrimSpace(cfg.MosaicKeying))
	if cfg.MosaicKeying == "" {
		cfg.MosaicKeying = MosaicKeyingBank
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
