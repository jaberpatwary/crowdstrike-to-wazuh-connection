// Command bridge pulls detections (Event Streams) and raw telemetry (FDR)
// from CrowdStrike Falcon, stores every event in Postgres for full audit
// history, and forwards a normalized copy to a JSON-lines file that Wazuh
// tails via its localfile log collector.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/youruser/crowdstrike-wazuh-bridge/internal/bridge"
	"github.com/youruser/crowdstrike-wazuh-bridge/internal/config"
	"github.com/youruser/crowdstrike-wazuh-bridge/internal/crowdstrike"
	"github.com/youruser/crowdstrike-wazuh-bridge/internal/logging"
	"github.com/youruser/crowdstrike-wazuh-bridge/internal/models"
	"github.com/youruser/crowdstrike-wazuh-bridge/internal/observability"
	"github.com/youruser/crowdstrike-wazuh-bridge/internal/storage"
	"github.com/youruser/crowdstrike-wazuh-bridge/internal/wazuh"
)

// wazuhDoc is the shape actually written to the Wazuh output file: lean,
// flat-ish, and stable, so Wazuh decoders/rules have a predictable schema
// regardless of which CrowdStrike feed the event came from.
type wazuhDoc struct {
	ID                  string         `json:"id"`
	Source              models.Source  `json:"source"`
	EventType           string         `json:"event_type"`
	AID                 string         `json:"aid,omitempty"`
	Hostname            string         `json:"hostname,omitempty"`
	CrowdStrikeHostname string         `json:"crowdstrike_hostname,omitempty"`
	Severity            string         `json:"severity,omitempty"`
	Tactic              string         `json:"tactic,omitempty"`
	Technique           string         `json:"technique,omitempty"`
	OccurredAt          string         `json:"occurred_at"`
	Raw                 map[string]any `json:"raw"`
}

func toWazuhDoc(id string, ev models.Event) wazuhDoc {
	return wazuhDoc{
		ID:                  id,
		Source:              ev.Source,
		EventType:           ev.EventType,
		AID:                 ev.AID,
		Hostname:            ev.Hostname,
		CrowdStrikeHostname: ev.Hostname,
		Severity:            ev.Severity,
		Tactic:              ev.Tactic,
		Technique:           ev.Technique,
		OccurredAt:          ev.OccurredAt.Format("2006-01-02T15:04:05.000Z07:00"),
		Raw:                 ev.Raw,
	}
}

func main() {
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "config error: %v\n", err)
		os.Exit(1)
	}

	logger, err := logging.New(cfg.LogLevel)
	if err != nil {
		fmt.Fprintf(os.Stderr, "logging configuration error: %v\n", err)
		return
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	pg, err := storage.NewPostgres(ctx, cfg.PGHost, cfg.PGPort, cfg.PGUser, cfg.PGPassword, cfg.PGDatabase, cfg.PGSSLMode)
	if err != nil {
		logger.Fatal().Err(err).Msg("Postgres initialization failed")
	}
	defer pg.Close()

	wazuhWriter, err := wazuh.NewWriter(cfg.WazuhOutputPath, cfg.WazuhMaxFileMB, cfg.WazuhMaxBackups)
	if err != nil {
		logger.Fatal().Err(err).Msg("Wazuh writer initialization failed")
	}
	defer wazuhWriter.Close()

	metrics := observability.NewMetrics()
	metricsServer := observability.NewServer(cfg.MetricsListenAddr, metrics, logger)
	if err := metricsServer.Start(); err != nil {
		logger.Fatal().Err(err).Str("address", cfg.MetricsListenAddr).Msg("health and metrics server initialization failed")
	}

	eventHandler := bridge.NewHandler(pg, wazuhWriter, metrics, cfg.ShutdownTimeout, func(id string, ev models.Event) any {
		return toWazuhDoc(id, ev)
	})

	eventHandler.SetForwardFilter(func(ev models.Event) bool {
		typeName := strings.ToLower(ev.EventType)
		return strings.Contains(typeName, "detection")
	})

	handleEvent := func(ev models.Event) error {
		if ev.OccurredAt.Before(cfg.EventsNotBefore) {
			metrics.RecordDroppedBeforeCutoff(ev.Source)
			return nil
		}
		return eventHandler.Handle(ev)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(cfg.PollInterval)
		defer ticker.Stop()
		for {
			replayCtx, replayCancel := context.WithTimeout(ctx, cfg.ShutdownTimeout)
			err := eventHandler.ReplayPending(replayCtx, 100)
			replayCancel()
			if err != nil && ctx.Err() == nil {
				logger.Warn().Err(err).Msg("pending Wazuh delivery retry failed")
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	tokens := crowdstrike.NewTokenSource(cfg.CSBaseURL, cfg.CSClientID, cfg.CSClientSecret)

	if cfg.EventStreamsEnabled {
		esClient := crowdstrike.NewEventStreamsClient(cfg.CSBaseURL, cfg.EventStreamsAppID, tokens, logger)
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := esClient.Run(ctx, handleEvent); err != nil && ctx.Err() == nil {
				logger.Error().Err(err).Str("component", "event_streams").Msg("consumer stopped")
			}
		}()
		logger.Info().Str("component", "event_streams").Msg("consumer started")
	}

	if cfg.FDREnabled {
		fdrConsumer, err := crowdstrike.NewFDRConsumer(ctx, cfg.FDRAWSRegion, cfg.FDRSQSQueueURL, cfg.FDRAWSAccessKeyID, cfg.FDRAWSSecretAccessKey, logger)
		if err != nil {
			logger.Fatal().Err(err).Msg("FDR consumer initialization failed")
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := fdrConsumer.Run(ctx, handleEvent); err != nil && ctx.Err() == nil {
				logger.Error().Err(err).Str("component", "fdr").Msg("consumer stopped")
			}
		}()
		logger.Info().Str("component", "fdr").Msg("consumer started")
	}

	logger.Info().Msg("bridge running")
	<-ctx.Done()
	logger.Info().Msg("shutdown signal received; stopping intake and draining active events")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer shutdownCancel()
	if err := metricsServer.Shutdown(shutdownCtx); err != nil {
		logger.Warn().Err(err).Msg("health and metrics server shutdown timed out")
	}

	workersDone := make(chan struct{})
	go func() {
		wg.Wait()
		close(workersDone)
	}()

	select {
	case <-workersDone:
		logger.Info().Msg("shutdown complete")
	case <-shutdownCtx.Done():
		logger.Error().Dur("timeout", cfg.ShutdownTimeout).Msg("shutdown grace period expired while waiting for consumers")
	}
}
