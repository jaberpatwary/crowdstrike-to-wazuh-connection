// Package bridge contains the durable event-delivery path shared by both feeds.
package bridge

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/youruser/crowdstrike-wazuh-bridge/internal/models"
	"github.com/youruser/crowdstrike-wazuh-bridge/internal/observability"
)

type EventStore interface {
	InsertEvent(context.Context, models.Event) (string, error)
	IsHandled(context.Context, string) (bool, error)
	MarkForwarded(context.Context, string) error
	MarkSkipped(context.Context, string) error
	PendingEvents(context.Context, int) ([]models.Event, error)
}

type WazuhWriter interface {
	WriteEvent(any) error
}

type Renderer func(string, models.Event) any

// Handler stores an event before writing it to Wazuh. Each operation gets an
// independent bounded context so a SIGTERM stops intake without cancelling an
// event that has already been read from a CrowdStrike response.
type Handler struct {
	deliveryMu    sync.Mutex
	store         EventStore
	writer        WazuhWriter
	metrics       *observability.Metrics
	timeout       time.Duration
	render        Renderer
	forwardFilter func(models.Event) bool
}

func NewHandler(store EventStore, writer WazuhWriter, metrics *observability.Metrics, timeout time.Duration, render Renderer) *Handler {
	return &Handler{
		store:   store,
		writer:  writer,
		metrics: metrics,
		timeout: timeout,
		render:  render,
	}
}

func (h *Handler) SetForwardFilter(filter func(models.Event) bool) {
	h.forwardFilter = filter
}

func (h *Handler) Handle(ev models.Event) error {
	h.metrics.RecordReceived(ev.Source)

	eventCtx, cancel := context.WithTimeout(context.Background(), h.timeout)
	defer cancel()

	id, err := h.store.InsertEvent(eventCtx, ev)
	if err != nil {
		h.metrics.RecordFailed(ev.Source)
		return fmt.Errorf("storing event: %w", err)
	}
	handled, err := h.store.IsHandled(eventCtx, id)
	if err != nil {
		h.metrics.RecordFailed(ev.Source)
		return fmt.Errorf("checking event %s delivery state: %w", id, err)
	}
	if handled {
		return nil
	}
	return h.forwardStored(eventCtx, id, ev)
}

func (h *Handler) forwardStored(ctx context.Context, id string, ev models.Event) error {
	h.deliveryMu.Lock()
	defer h.deliveryMu.Unlock()
	handled, err := h.store.IsHandled(ctx, id)
	if err != nil {
		return fmt.Errorf("checking event %s delivery state: %w", id, err)
	}
	if handled {
		return nil
	}
	if h.forwardFilter != nil && !h.forwardFilter(ev) {
		h.metrics.RecordWazuhSkipped(ev.Source)
		if err := h.store.MarkSkipped(ctx, id); err != nil {
			return fmt.Errorf("marking event %s as skipped: %w", id, err)
		}
		return nil
	}

	if err := h.writer.WriteEvent(h.render(id, ev)); err != nil {
		h.metrics.RecordFailed(ev.Source)
		return fmt.Errorf("writing event %s to Wazuh: %w", id, err)
	}
	h.metrics.RecordForwarded(ev.Source)

	if err := h.store.MarkForwarded(ctx, id); err != nil {
		h.metrics.RecordFailed(ev.Source)
		return fmt.Errorf("marking event %s as forwarded: %w", id, err)
	}
	return nil
}

// ReplayPending drains the durable outbox. Calling it periodically retries
// rows left pending by a process crash or a temporary Wazuh write failure.
func (h *Handler) ReplayPending(ctx context.Context, limit int) error {
	if limit <= 0 {
		limit = 100
	}
	for {
		events, err := h.store.PendingEvents(ctx, limit)
		if err != nil {
			return err
		}
		if len(events) == 0 {
			return nil
		}
		for _, ev := range events {
			if err := h.forwardStored(ctx, ev.ID, ev); err != nil {
				return err
			}
		}
	}
}
