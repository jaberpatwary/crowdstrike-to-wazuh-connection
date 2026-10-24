package storage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strconv"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/youruser/crowdstrike-wazuh-bridge/internal/models"
)

type Postgres struct {
	pool *pgxpool.Pool
}

func NewPostgres(ctx context.Context, host string, port int, user, password, database, sslmode string) (*Postgres, error) {
	connURL := url.URL{
		Scheme:   "postgres",
		User:     url.UserPassword(user, password),
		Host:     net.JoinHostPort(host, strconv.Itoa(port)),
		Path:     "/" + database,
		RawQuery: url.Values{"sslmode": []string{sslmode}}.Encode(),
	}
	pool, err := pgxpool.New(ctx, connURL.String())
	if err != nil {
		return nil, fmt.Errorf("connecting to postgres: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("pinging postgres: %w", err)
	}
	pg := &Postgres{pool: pool}
	if err := pg.migrate(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return pg, nil
}

func (p *Postgres) Close() {
	p.pool.Close()
}

// migrate creates the schema if it doesn't exist yet. Kept intentionally
// simple (no external migration tool) since this is a single, append-mostly
// audit table; grow this into golang-migrate/goose if the schema evolves.
func (p *Postgres) migrate(ctx context.Context) error {
	const ddl = `
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS crowdstrike_events (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source       TEXT        NOT NULL,
    event_type   TEXT,
    aid          TEXT,
    hostname     TEXT,
    severity     TEXT,
    tactic       TEXT,
    technique    TEXT,
    occurred_at  TIMESTAMPTZ NOT NULL,
    ingested_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    forwarded_to_wazuh BOOLEAN NOT NULL DEFAULT FALSE,
    event_key    TEXT,
    wazuh_status TEXT NOT NULL DEFAULT 'pending',
    raw_payload  JSONB       NOT NULL
);

ALTER TABLE crowdstrike_events ADD COLUMN IF NOT EXISTS event_key TEXT;
ALTER TABLE crowdstrike_events ADD COLUMN IF NOT EXISTS wazuh_status TEXT NOT NULL DEFAULT 'pending';
UPDATE crowdstrike_events SET wazuh_status = 'forwarded' WHERE forwarded_to_wazuh = TRUE AND wazuh_status = 'pending';
CREATE UNIQUE INDEX IF NOT EXISTS idx_cs_events_event_key ON crowdstrike_events (event_key);

CREATE INDEX IF NOT EXISTS idx_cs_events_occurred_at ON crowdstrike_events (occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_cs_events_source      ON crowdstrike_events (source);
CREATE INDEX IF NOT EXISTS idx_cs_events_aid          ON crowdstrike_events (aid);
CREATE INDEX IF NOT EXISTS idx_cs_events_event_type   ON crowdstrike_events (event_type);
`
	_, err := p.pool.Exec(ctx, ddl)
	if err != nil {
		return fmt.Errorf("running migration: %w", err)
	}
	return nil
}

// InsertEvent persists one event idempotently by payload key and returns its
// stable row ID for both retries and Wazuh delivery.
func (p *Postgres) InsertEvent(ctx context.Context, ev models.Event) (string, error) {
	key := ev.DedupKey
	if key == "" {
		payload := ev.RawPayload
		if len(payload) == 0 {
			var err error
			payload, err = json.Marshal(ev.Raw)
			if err != nil {
				return "", fmt.Errorf("encoding event payload: %w", err)
			}
		}
		sum := sha256.Sum256(append(append([]byte(string(ev.Source)+":"), payload...), 0))
		key = hex.EncodeToString(sum[:])
	}
	payload := any(ev.Raw)
	if len(ev.RawPayload) > 0 {
		payload = json.RawMessage(ev.RawPayload)
	}
	const q = `
INSERT INTO crowdstrike_events
    (source, event_type, aid, hostname, severity, tactic, technique, occurred_at, ingested_at, raw_payload, event_key)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
ON CONFLICT (event_key) DO UPDATE SET event_key = EXCLUDED.event_key
RETURNING id`

	var id string
	err := p.pool.QueryRow(ctx, q,
		ev.Source, ev.EventType, ev.AID, ev.Hostname, ev.Severity, ev.Tactic, ev.Technique,
		ev.OccurredAt, ev.IngestedAt, payload, key,
	).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("inserting event: %w", err)
	}
	return id, nil
}

// MarkForwarded flags a stored event as having been written to the Wazuh
// output file, so a restart of the bridge can tell what's already shipped.
func (p *Postgres) MarkForwarded(ctx context.Context, id string) error {
	_, err := p.pool.Exec(ctx, `UPDATE crowdstrike_events SET forwarded_to_wazuh = TRUE, wazuh_status = 'forwarded' WHERE id = $1`, id)
	return err
}

func (p *Postgres) MarkSkipped(ctx context.Context, id string) error {
	_, err := p.pool.Exec(ctx, `UPDATE crowdstrike_events SET wazuh_status = 'skipped' WHERE id = $1`, id)
	return err
}

func (p *Postgres) IsHandled(ctx context.Context, id string) (bool, error) {
	var handled bool
	err := p.pool.QueryRow(ctx, `SELECT wazuh_status <> 'pending' FROM crowdstrike_events WHERE id = $1`, id).Scan(&handled)
	return handled, err
}

func (p *Postgres) PendingEvents(ctx context.Context, limit int) ([]models.Event, error) {
	rows, err := p.pool.Query(ctx, `SELECT id::text, source, event_type, aid, hostname, severity, tactic, technique, occurred_at, ingested_at, raw_payload FROM crowdstrike_events WHERE wazuh_status = 'pending' AND event_type ILIKE '%detection%' ORDER BY ingested_at, id LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("querying pending Wazuh events: %w", err)
	}
	defer rows.Close()
	var events []models.Event
	for rows.Next() {
		var ev models.Event
		var raw []byte
		if err := rows.Scan(&ev.ID, &ev.Source, &ev.EventType, &ev.AID, &ev.Hostname, &ev.Severity, &ev.Tactic, &ev.Technique, &ev.OccurredAt, &ev.IngestedAt, &raw); err != nil {
			return nil, fmt.Errorf("scanning pending Wazuh event: %w", err)
		}
		ev.RawPayload = append([]byte(nil), raw...)
		if err := json.Unmarshal(raw, &ev.Raw); err != nil {
			return nil, fmt.Errorf("decoding pending Wazuh event %s: %w", ev.ID, err)
		}
		events = append(events, ev)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("reading pending Wazuh events: %w", err)
	}
	return events, nil
}
