package models

import "time"

// Source identifies which CrowdStrike feed an event came from.
type Source string

const (
	SourceEventStreams Source = "event_streams" // real-time detections/events
	SourceFDR          Source = "fdr"           // Falcon Data Replicator bulk telemetry
)

// Event is the normalized shape stored in Postgres and forwarded to Wazuh.
// RawPayload keeps the untouched original JSON so nothing is ever lost,
// even if CrowdStrike adds fields we don't explicitly map.
type Event struct {
	ID         string         `json:"id"`            // generated UUID assigned by the event store
	DedupKey   string         `json:"-"`             // stable source payload key for retry-safe ingestion
	Source     Source         `json:"source"`        // event_streams | fdr
	EventType  string         `json:"event_type"`    // e.g. DetectionSummaryEvent, ProcessRollup2
	AID        string         `json:"aid,omitempty"` // CrowdStrike agent/sensor ID
	Hostname   string         `json:"hostname,omitempty"`
	Severity   string         `json:"severity,omitempty"`
	Tactic     string         `json:"tactic,omitempty"`
	Technique  string         `json:"technique,omitempty"`
	OccurredAt time.Time      `json:"occurred_at"`
	IngestedAt time.Time      `json:"ingested_at"`
	RawPayload []byte         `json:"-"` // stored separately, not re-embedded in the JSON we emit
	Raw        map[string]any `json:"raw"`
}
