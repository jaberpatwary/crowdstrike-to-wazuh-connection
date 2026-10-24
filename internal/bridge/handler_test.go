package bridge

import (
	"context"
	"testing"
	"time"

	"github.com/youruser/crowdstrike-wazuh-bridge/internal/models"
	"github.com/youruser/crowdstrike-wazuh-bridge/internal/observability"
)

type blockingStore struct {
	started chan struct{}
	release chan struct{}
	marked  bool
}

func (s *blockingStore) InsertEvent(context.Context, models.Event) (string, error) {
	close(s.started)
	<-s.release
	return "event-id", nil
}

func (s *blockingStore) IsHandled(context.Context, string) (bool, error) { return false, nil }

func (s *blockingStore) MarkSkipped(context.Context, string) error { return nil }

func (s *blockingStore) PendingEvents(context.Context, int) ([]models.Event, error) { return nil, nil }

func (s *blockingStore) MarkForwarded(context.Context, string) error {
	s.marked = true
	return nil
}

type recordingWriter struct {
	written bool
}

func (w *recordingWriter) WriteEvent(any) error {
	w.written = true
	return nil
}

// This simulates SIGTERM's cancellation of the intake context while an event
// is already being delivered. Handler intentionally uses its bounded, separate
// context and must complete the event before shutdown returns.
func TestHandleCompletesAfterIntakeCancellation(t *testing.T) {
	store := &blockingStore{started: make(chan struct{}), release: make(chan struct{})}
	writer := &recordingWriter{}
	handler := NewHandler(store, writer, observability.NewMetrics(), time.Second, func(string, models.Event) any {
		return map[string]string{"ok": "true"}
	})

	intakeCtx, cancelIntake := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		result <- handler.Handle(models.Event{Source: models.SourceEventStreams})
	}()

	select {
	case <-store.started:
	case <-time.After(time.Second):
		t.Fatal("event delivery did not start")
	}
	cancelIntake()
	select {
	case <-intakeCtx.Done():
	case <-time.After(time.Second):
		t.Fatal("intake context was not cancelled")
	}
	close(store.release)

	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("Handle() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("in-flight event was not drained")
	}
	if !writer.written || !store.marked {
		t.Fatal("event was not fully forwarded and marked")
	}
}
