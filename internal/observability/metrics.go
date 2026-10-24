// Package observability exposes process health and Prometheus metrics.
package observability

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog"

	"github.com/youruser/crowdstrike-wazuh-bridge/internal/models"
)

type Metrics struct {
	registry            *prometheus.Registry
	received            *prometheus.CounterVec
	forwarded           *prometheus.CounterVec
	failed              *prometheus.CounterVec
	lastSuccessful      *prometheus.GaugeVec
	droppedBeforeCutoff *prometheus.CounterVec
	wazuhSkipped        *prometheus.CounterVec
}

func NewMetrics() *Metrics {
	m := &Metrics{
		registry: prometheus.NewRegistry(),
		received: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "events_received_total",
			Help: "Number of CrowdStrike events accepted for processing.",
		}, []string{"source"}),
		forwarded: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "events_forwarded_total",
			Help: "Number of events written to the Wazuh JSON-lines output.",
		}, []string{"source"}),
		failed: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "events_failed_total",
			Help: "Number of events that failed storage or Wazuh forwarding.",
		}, []string{"source"}),
		droppedBeforeCutoff: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "events_dropped_before_cutoff_total",
			Help: "Number of CrowdStrike events ignored because their event time is before EVENTS_NOT_BEFORE.",
		}, []string{"source"}),
		wazuhSkipped: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "events_skipped_wazuh_total",
			Help: "Number of CrowdStrike events stored in PostgreSQL but intentionally not forwarded to Wazuh by the configured filter.",
		}, []string{"source"}),
		lastSuccessful: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "last_successful_event_timestamp",
			Help: "Unix timestamp of the most recently forwarded event.",
		}, []string{"source"}),
	}
	m.registry.MustRegister(m.received, m.forwarded, m.failed, m.lastSuccessful, m.droppedBeforeCutoff, m.wazuhSkipped)
	return m
}

func (m *Metrics) RecordReceived(source models.Source) {
	m.received.WithLabelValues(string(source)).Inc()
}

func (m *Metrics) RecordForwarded(source models.Source) {
	m.forwarded.WithLabelValues(string(source)).Inc()
	m.lastSuccessful.WithLabelValues(string(source)).Set(float64(time.Now().Unix()))
}

func (m *Metrics) RecordDroppedBeforeCutoff(source models.Source) {
	m.droppedBeforeCutoff.WithLabelValues(string(source)).Inc()
}

func (m *Metrics) RecordWazuhSkipped(source models.Source) {
	m.wazuhSkipped.WithLabelValues(string(source)).Inc()
}

func (m *Metrics) RecordFailed(source models.Source) {
	m.failed.WithLabelValues(string(source)).Inc()
}

func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{})
}

type Server struct {
	server  *http.Server
	logger  zerolog.Logger
	healthy atomic.Bool
}

func NewServer(addr string, metrics *Metrics, logger zerolog.Logger) *Server {
	s := &Server{logger: logger}
	s.healthy.Store(true)

	mux := http.NewServeMux()
	mux.Handle("/metrics", metrics.Handler())
	mux.HandleFunc("/healthz", s.healthz)
	s.server = &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	return s
}

func (s *Server) Start() error {
	listener, err := net.Listen("tcp", s.server.Addr)
	if err != nil {
		return err
	}
	s.logger.Info().Str("address", listener.Addr().String()).Msg("health and metrics server started")
	go func() {
		if err := s.server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.logger.Error().Err(err).Msg("health and metrics server stopped")
		}
	}()
	return nil
}

func (s *Server) Shutdown(ctx context.Context) error {
	s.healthy.Store(false)
	return s.server.Shutdown(ctx)
}

func (s *Server) healthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if !s.healthy.Load() {
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "shutting_down"})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}
