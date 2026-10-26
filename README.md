# CrowdStrike Wazuh Bridge

A Go service that consumes CrowdStrike Falcon Event Streams, stores full event history in PostgreSQL, and forwards JSON events to a shared Wazuh log volume.

## Current setup

- Event Streams is enabled and connected.
- The bridge writes to the host PostgreSQL database configured in .env (wazuh, crowdstrike_events).
- Compose does not launch a second PostgreSQL server; PG_HOST selects the database the bridge uses.
- Wazuh tails /var/ossec/logs/crowdstrike/crowdstrike-events.json.
- The Wazuh indexer, manager, and dashboard run in this Compose project and reuse their existing persistent volumes.
- FDR is optional and currently disabled. It requires CrowdStrike provisioning of an SQS queue and S3 access credentials.

## Start and monitor

From this directory, run:

    make start
    make status
    make logs

make start builds and starts the Wazuh stack and bridge in this Compose project. The bridge's health and Prometheus metrics endpoints are bound to localhost only:

- Health: http://localhost:18080/healthz
- Metrics: http://localhost:18080/metrics

The Wazuh Dashboard is at https://localhost:8443.

## View CrowdStrike data

### PostgreSQL / pgAdmin

Refresh the wazuh database in pgAdmin, then open public.crowdstrike_events. The bridge creates this table on startup. Useful Query Tool SQL:

    SELECT COUNT(*), MAX(ingested_at) FROM crowdstrike_events;

    SELECT occurred_at, event_type, hostname, severity, tactic, technique, raw_payload
    FROM crowdstrike_events
    ORDER BY ingested_at DESC
    LIMIT 50;

Use the values in .env for the database connection. From the bridge container, the host database address is host.docker.internal, not localhost.

### Wazuh Dashboard

Open Threat Hunting and select wazuh-alerts-*. Useful filters:

    rule.groups:crowdstrike_detection
    data.severity:High
    data.severity:Medium
    data.severity:Low
    data.event_type:EppDetectionSummaryEvent
    data.aid:*

Select wazuh-archives-* to inspect raw CrowdStrike events. Wazuh stores these custom fields under data (for example data.aid, data.hostname, data.severity, and data.event_type). The agent.id field is Wazuh's log source agent; because this bridge writes through the manager localfile collector, it can show 000. Use data.aid for the CrowdStrike sensor ID. Use rule.groups:crowdstrike_event for all bridge events, or rule.groups:crowdstrike_detection for detections only.

## Configuration

Keep credentials in .env; never commit this file. Start from .env.example on a new machine.

Wazuh runtime credentials, certificates, and service configuration are stored under `wazuh-runtime/`. That folder is git-ignored because it contains secrets and local runtime files.

Required for Event Streams:

- CS_CLIENT_ID and CS_CLIENT_SECRET from a Falcon API client with Event Streams read access.
- CS_BASE_URL matching the Falcon cloud region.
- EVENT_STREAMS_ENABLED=true.

PostgreSQL settings use the PG_* variables. The configured PostgreSQL server must accept connections from Docker. The current host PostgreSQL connection is host.docker.internal:5432.

Detection delivery uses a PostgreSQL outbox. Pending rows are retried periodically after write failures or restarts, and repeated copies of the same source payload reuse the same event row. File delivery is at-least-once: a process crash after writing the file but before recording success can produce a duplicate Wazuh line.

EVENTS_NOT_BEFORE sets the earliest CrowdStrike event timestamp to store or forward. It is set in this workspace to 2026-10-21T00:00:00+06:00; backlog events before that cutoff are discarded and counted by events_dropped_before_cutoff_total. The default when unset is midnight today in Asia/Dhaka.

### Optional Falcon Data Replicator

FDR is disabled by default. Enable it only after CrowdStrike has provisioned the FDR SQS/S3 integration and the queue, region, and AWS credentials are available:

    FDR_ENABLED=true
    FDR_SQS_QUEUE_URL=...
    FDR_AWS_REGION=...
    FDR_AWS_ACCESS_KEY_ID=...
    FDR_AWS_SECRET_ACCESS_KEY=...

## Wazuh integration

The active Wazuh manager is configured to tail the shared CrowdStrike event file, and the CrowdStrike rules are installed in its local_rules.xml. Source snippets remain in wazuh-rules/ for reference. Rule IDs 110100-110106 cover general events and Low/Medium/High/Critical detections.

## Development

Go 1.22+ and Docker Compose are required.

    go build ./...
    go test ./...

The container uses a multi-stage build and runs as a small distroless image.
PostgreSQL is the durable event archive. The Wazuh JSON output is rotated when it reaches WAZUH_MAX_FILE_MB and only WAZUH_MAX_BACKUPS rotated files are retained; older Wazuh log files can therefore age out while PostgreSQL rows remain. The bridge does not delete PostgreSQL rows. Event Streams only delivers event types enabled for the Falcon API client and available to the tenant; low activity can mean there were no new matching events. FDR is a separate optional source and remains disabled until CrowdStrike provisions its SQS/S3 integration.



