package observability

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rs/zerolog"

	"github.com/youruser/crowdstrike-wazuh-bridge/internal/models"
)

func TestHealthAndMetricsHandlers(t *testing.T) {
	metrics := NewMetrics()
	metrics.RecordReceived(models.SourceEventStreams)
	metrics.RecordForwarded(models.SourceEventStreams)
	metrics.RecordFailed(models.SourceFDR)

	server := NewServer(":0", metrics, zerolog.Nop())
	healthRequest := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	healthResponse := httptest.NewRecorder()
	server.healthz(healthResponse, healthRequest)
	if healthResponse.Code != http.StatusOK {
		t.Fatalf("health status = %d, want %d", healthResponse.Code, http.StatusOK)
	}
	if !strings.Contains(healthResponse.Body.String(), `"status":"ok"`) {
		t.Fatalf("unexpected health response: %s", healthResponse.Body.String())
	}

	metricsResponse := httptest.NewRecorder()
	metrics.Handler().ServeHTTP(metricsResponse, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if metricsResponse.Code != http.StatusOK {
		t.Fatalf("metrics status = %d, want %d", metricsResponse.Code, http.StatusOK)
	}
	body := metricsResponse.Body.String()
	for _, metricName := range []string{"events_received_total", "events_forwarded_total", "last_successful_event_timestamp"} {
		if !strings.Contains(body, metricName) {
			t.Errorf("metrics response did not include %s", metricName)
		}
	}
}
