package crowdstrike

import (
	"testing"
	"time"

	"github.com/youruser/crowdstrike-wazuh-bridge/internal/models"
)

func TestParseEventStreamLine(t *testing.T) {
	line := `{
		"metadata": {
			"eventType": "DetectionSummaryEvent",
			"eventCreationTime": 1715794205123
		},
		"event": {
			"AgentId": "7f4a6f1a96ed4f30b06e3f9d5f1f7eaf",
			"Hostname": "workstation-17",
			"Severity": "High",
			"Tactic": "Execution",
			"Technique": "T1059"
		}
	}`

	got, err := parseEventStreamLine(line)
	if err != nil {
		t.Fatalf("parseEventStreamLine() error = %v", err)
	}
	if got.Source != models.SourceEventStreams {
		t.Errorf("Source = %q, want %q", got.Source, models.SourceEventStreams)
	}
	if got.EventType != "DetectionSummaryEvent" || got.AID != "7f4a6f1a96ed4f30b06e3f9d5f1f7eaf" {
		t.Errorf("unexpected core fields: %+v", got)
	}
	if got.Hostname != "workstation-17" || got.Severity != "High" || got.Tactic != "Execution" || got.Technique != "T1059" {
		t.Errorf("unexpected event fields: %+v", got)
	}
	wantTime := time.UnixMilli(1715794205123).UTC()
	if !got.OccurredAt.Equal(wantTime) {
		t.Errorf("OccurredAt = %s, want %s", got.OccurredAt, wantTime)
	}
	if len(got.RawPayload) == 0 || got.Raw == nil {
		t.Error("raw payload was not retained")
	}
}

func TestParseEventStreamLineEdgeCases(t *testing.T) {
	tests := []struct {
		name    string
		line    string
		wantErr bool
	}{
		{name: "malformed JSON", line: `{"metadata":`, wantErr: true},
		{name: "missing metadata and event", line: `{"trace_id":"abc123"}`},
		{name: "metadata without event", line: `{"metadata":{"eventType":"AuthActivityAuditEvent"}}`},
		{name: "event without metadata", line: `{"event":{"AgentId":"aid-123","Hostname":"host-1"}}`},
		{name: "wrong nested field types", line: `{"metadata":"not-an-object","event":[]}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseEventStreamLine(tt.line)
			if tt.wantErr {
				if err == nil {
					t.Fatal("parseEventStreamLine() error = nil, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("parseEventStreamLine() error = %v", err)
			}
			if got.Source != models.SourceEventStreams || got.Raw == nil {
				t.Errorf("unexpected defensive parse result: %+v", got)
			}
		})
	}
}
