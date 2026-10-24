// Package config loads all runtime configuration from environment variables
// (optionally via a .env file for local development). Nothing secret is ever
// hardcoded or logged.
package config

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/joho/godotenv"
)

type Config struct {
	// --- CrowdStrike API (OAuth2 client credentials) ---
	CSClientID     string
	CSClientSecret string
	CSBaseURL      string // e.g. https://api.crowdstrike.com (or us-2 / eu-1 region URL)

	// --- Event Streams (real-time detections/events) ---
	EventStreamsEnabled bool
	EventStreamsAppID   string // arbitrary string identifying this consumer to CrowdStrike

	// --- Falcon Data Replicator (bulk raw telemetry via AWS SQS + S3) ---
	FDREnabled     bool
	FDRSQSQueueURL string
	FDRAWSRegion   string
	// FDR credentials are normally supplied by CrowdStrike as a dedicated
	// IAM user; keep them separate from any other AWS credentials you use.
	FDRAWSAccessKeyID     string
	FDRAWSSecretAccessKey string

	// --- PostgreSQL (full event/audit history) ---
	PGHost     string
	PGPort     int
	PGUser     string
	PGPassword string
	PGDatabase string
	PGSSLMode  string

	// --- Wazuh output (JSON-lines file, tailed by Wazuh's localfile collector) ---
	WazuhOutputPath string // e.g. /var/ossec/logs/crowdstrike/crowdstrike-events.json
	WazuhMaxFileMB  int    // size before rotation
	WazuhMaxBackups int

	// --- Misc ---
	PollInterval      time.Duration
	LogLevel          string
	MetricsListenAddr string
	ShutdownTimeout   time.Duration
	EventsNotBefore   time.Time
}

func Load() (*Config, error) {
	// Best effort: load .env if present (local/dev only). In Docker/production
	// the real environment variables are injected by docker-compose/secrets.
	_ = godotenv.Load()

	streamsEnabled, err := getenvBool("EVENT_STREAMS_ENABLED", true)
	if err != nil {
		return nil, err
	}
	fdrEnabled, err := getenvBool("FDR_ENABLED", false)
	if err != nil {
		return nil, err
	}
	pgPort, err := getenvInt("PG_PORT", 5432)
	if err != nil {
		return nil, err
	}
	maxFileMB, err := getenvInt("WAZUH_MAX_FILE_MB", 100)
	if err != nil {
		return nil, err
	}
	maxBackups, err := getenvInt("WAZUH_MAX_BACKUPS", 5)
	if err != nil {
		return nil, err
	}
	pollSeconds, err := getenvInt("POLL_INTERVAL_SECONDS", 30)
	if err != nil {
		return nil, err
	}
	shutdownSeconds, err := getenvInt("SHUTDOWN_TIMEOUT_SECONDS", 30)
	if err != nil {
		return nil, err
	}

	cfg := &Config{
		CSClientID:     os.Getenv("CS_CLIENT_ID"),
		CSClientSecret: os.Getenv("CS_CLIENT_SECRET"),
		CSBaseURL:      getenvDefault("CS_BASE_URL", "https://api.crowdstrike.com"),

		EventStreamsEnabled: streamsEnabled,
		EventStreamsAppID:   getenvDefault("EVENT_STREAMS_APP_ID", "wazuh-bridge"),

		FDREnabled:            fdrEnabled,
		FDRSQSQueueURL:        os.Getenv("FDR_SQS_QUEUE_URL"),
		FDRAWSRegion:          getenvDefault("FDR_AWS_REGION", "us-west-1"),
		FDRAWSAccessKeyID:     os.Getenv("FDR_AWS_ACCESS_KEY_ID"),
		FDRAWSSecretAccessKey: os.Getenv("FDR_AWS_SECRET_ACCESS_KEY"),

		PGHost:     getenvDefault("PG_HOST", "host.docker.internal"),
		PGPort:     pgPort,
		PGUser:     getenvDefault("PG_USER", "postgres"),
		PGPassword: os.Getenv("PG_PASSWORD"),
		PGDatabase: getenvDefault("PG_DATABASE", "wazuh"),
		PGSSLMode:  getenvDefault("PG_SSLMODE", "disable"),

		WazuhOutputPath: getenvDefault("WAZUH_OUTPUT_PATH", "/var/ossec/logs/crowdstrike/crowdstrike-events.json"),
		WazuhMaxFileMB:  maxFileMB,
		WazuhMaxBackups: maxBackups,

		PollInterval:      time.Duration(pollSeconds) * time.Second,
		LogLevel:          getenvDefault("LOG_LEVEL", "info"),
		MetricsListenAddr: getenvDefault("METRICS_LISTEN_ADDR", ":8080"),
		ShutdownTimeout:   time.Duration(shutdownSeconds) * time.Second,
	}

	cutoffText := os.Getenv("EVENTS_NOT_BEFORE")
	if cutoffText == "" {
		dhaka := time.FixedZone("Asia/Dhaka", 6*60*60)
		now := time.Now().In(dhaka)
		cfg.EventsNotBefore = time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, dhaka)
	} else {
		cutoff, err := time.Parse(time.RFC3339, cutoffText)
		if err != nil {
			return nil, fmt.Errorf("invalid EVENTS_NOT_BEFORE %q; use RFC3339, for example 2026-10-21T00:00:00+06:00: %w", cutoffText, err)
		}
		cfg.EventsNotBefore = cutoff
	}
	if cfg.PGPort < 1 || cfg.PGPort > 65535 {
		return nil, fmt.Errorf("PG_PORT must be between 1 and 65535")
	}
	if cfg.WazuhMaxFileMB <= 0 {
		return nil, fmt.Errorf("WAZUH_MAX_FILE_MB must be greater than zero")
	}
	if cfg.WazuhMaxBackups < 0 {
		return nil, fmt.Errorf("WAZUH_MAX_BACKUPS cannot be negative")
	}
	if cfg.PollInterval <= 0 {
		return nil, fmt.Errorf("POLL_INTERVAL_SECONDS must be greater than zero")
	}
	if cfg.ShutdownTimeout <= 0 {
		return nil, fmt.Errorf("SHUTDOWN_TIMEOUT_SECONDS must be greater than zero")
	}
	if !cfg.EventStreamsEnabled && !cfg.FDREnabled {
		return nil, fmt.Errorf("at least one source must be enabled: EVENT_STREAMS_ENABLED or FDR_ENABLED")
	}
	if cfg.EventStreamsEnabled && (cfg.CSClientID == "" || cfg.CSClientSecret == "") {
		return nil, fmt.Errorf("CS_CLIENT_ID and CS_CLIENT_SECRET are required")
	}
	if (cfg.FDRAWSAccessKeyID == "") != (cfg.FDRAWSSecretAccessKey == "") {
		return nil, fmt.Errorf("FDR_AWS_ACCESS_KEY_ID and FDR_AWS_SECRET_ACCESS_KEY must be set together")
	}
	if cfg.FDREnabled && cfg.FDRSQSQueueURL == "" {
		return nil, fmt.Errorf("FDR_ENABLED=true but FDR_SQS_QUEUE_URL is not set")
	}
	return cfg, nil
}

func getenvDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func getenvBool(key string, def bool) (bool, error) {
	v := os.Getenv(key)
	if v == "" {
		return def, nil
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return false, fmt.Errorf("invalid %s value %q: %w", key, v, err)
	}
	return b, nil
}

func getenvInt(key string, def int) (int, error) {
	v := os.Getenv(key)
	if v == "" {
		return def, nil
	}
	i, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("invalid %s value %q: %w", key, v, err)
	}
	return i, nil
}
