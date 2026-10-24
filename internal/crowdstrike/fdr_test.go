package crowdstrike

import (
	"testing"
	"time"

	"github.com/youruser/crowdstrike-wazuh-bridge/internal/models"
)

func TestParseFDRLine(t *testing.T) {
	line := `{
		"event_simpleName": "ProcessRollup2",
		"aid": "7f4a6f1a96ed4f30b06e3f9d5f1f7eaf",
		"ComputerName": "production-web-02",
		"timestamp": 1715794205123,
		"CommandLine": "powershell.exe -EncodedCommand ..."
	}`

	got, err := parseFDRLine(line)
	if err != nil {
		t.Fatalf("parseFDRLine() error = %v", err)
	}
	if got.Source != models.SourceFDR {
		t.Errorf("Source = %q, want %q", got.Source, models.SourceFDR)
	}
	if got.EventType != "ProcessRollup2" || got.AID != "7f4a6f1a96ed4f30b06e3f9d5f1f7eaf" || got.Hostname != "production-web-02" {
		t.Errorf("unexpected core fields: %+v", got)
	}
	wantTime := time.UnixMilli(1715794205123).UTC()
	if !got.OccurredAt.Equal(wantTime) {
		t.Errorf("OccurredAt = %s, want %s", got.OccurredAt, wantTime)
	}
	if len(got.RawPayload) == 0 || got.Raw == nil {
		t.Error("raw payload was not retained")
	}
}

func TestParseFDRLineEdgeCases(t *testing.T) {
	tests := []struct {
		name    string
		line    string
		wantErr bool
	}{
		{name: "malformed JSON", line: `{"event_simpleName":`, wantErr: true},
		{name: "missing optional fields", line: `{"event_simpleName":"UserLogon"}`},
		{name: "wrong field types", line: `{"aid":42,"ComputerName":true,"timestamp":"not-a-number"}`},
		{name: "nested payload only", line: `{"ContextBaseFileName":"example.exe","UserName":"alice"}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseFDRLine(tt.line)
			if tt.wantErr {
				if err == nil {
					t.Fatal("parseFDRLine() error = nil, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("parseFDRLine() error = %v", err)
			}
			if got.Source != models.SourceFDR || got.Raw == nil {
				t.Errorf("unexpected defensive parse result: %+v", got)
			}
		})
	}
}
