package config

import (
	"strings"
	"testing"
)

func TestLoadRejectsInvalidBoolean(t *testing.T) {
	t.Setenv("EVENT_STREAMS_ENABLED", "sometimes")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "EVENT_STREAMS_ENABLED") {
		t.Fatalf("Load() error = %v, want an EVENT_STREAMS_ENABLED error", err)
	}
}

func TestLoadRejectsInvalidInteger(t *testing.T) {
	t.Setenv("EVENT_STREAMS_ENABLED", "true")
	t.Setenv("FDR_ENABLED", "false")
	t.Setenv("PG_PORT", "not-a-port")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "PG_PORT") {
		t.Fatalf("Load() error = %v, want a PG_PORT error", err)
	}
}
