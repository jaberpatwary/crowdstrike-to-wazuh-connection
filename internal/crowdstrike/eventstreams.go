package crowdstrike

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/rs/zerolog"

	"github.com/youruser/crowdstrike-wazuh-bridge/internal/models"
)

var (
	errStreamClosed   = errors.New("event streams data feed closed")
	errSessionRefresh = errors.New("event streams active session refresh required")
)

// EventHandler persists and forwards one normalized event. It returns an error
// so FDR can leave its SQS notification for redelivery if durable handling
// fails.
type EventHandler func(models.Event) error

// EventStreamsClient discovers and consumes CrowdStrike's Event Streams API,
// which delivers real-time detections and other platform events as a
// continuous newline-delimited JSON stream over a long-lived HTTP connection.
type EventStreamsClient struct {
	baseURL    string
	appID      string
	tokens     *TokenSource
	httpClient *http.Client
	breaker    *CircuitBreaker
	logger     zerolog.Logger
}

func NewEventStreamsClient(baseURL, appID string, tokens *TokenSource, logger zerolog.Logger) *EventStreamsClient {
	return &EventStreamsClient{
		baseURL: strings.TrimRight(baseURL, "/"),
		appID:   appID,
		tokens:  tokens,
		// No timeout here: this is a long-lived streaming connection.
		httpClient: &http.Client{},
		breaker:    NewCircuitBreaker(3, 30*time.Second),
		logger:     logger.With().Str("component", "event_streams").Logger(),
	}
}

type discoverResponse struct {
	Resources []feedResource `json:"resources"`
}

type feedResource struct {
	DataFeedURL string `json:"dataFeedURL"`
	Token       struct {
		Token string `json:"token"`
	} `json:"token"`
	RefreshActiveSessionInterval int `json:"refreshActiveSessionInterval"`
	SessionToken                 struct {
		Token string `json:"token"`
	} `json:"sessionToken"`
}

// discover asks CrowdStrike which data-feed URL and session token to use.
// CrowdStrike partitions the stream; for most single-CID setups there's one partition.
func (c *EventStreamsClient) discover(ctx context.Context) (*discoverResponse, error) {
	var out discoverResponse
	err := retry(ctx, c.breaker, defaultRetryPolicy, func() error {
		token, err := c.tokens.Token(ctx)
		if err != nil {
			return err
		}

		endpoint := fmt.Sprintf("%s/sensors/entities/datafeed/v2?appId=%s", c.baseURL, url.QueryEscape(c.appID))
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+token)

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return fmt.Errorf("event streams discover: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return &APIStatusError{Operation: "event streams discover", Status: resp.StatusCode}
		}

		var decoded discoverResponse
		if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
			return fmt.Errorf("decoding discover response: %w", err)
		}
		if len(decoded.Resources) == 0 {
			return fmt.Errorf("event streams discover returned no feed resources")
		}
		out = decoded
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// Run connects to the data feed and calls handle for every event received. It
// backs off on reconnects and forces a fresh OAuth token and data-feed session
// before CrowdStrike's advertised active-session deadline.
func (c *EventStreamsClient) Run(ctx context.Context, handle EventHandler) error {
	reconnectAttempt := 0
	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		handled, err := c.consumeOnce(ctx, handle)
		if errors.Is(err, errSessionRefresh) {
			c.tokens.Invalidate()
			c.logger.Info().Msg("refreshing active Event Streams session")
			reconnectAttempt = 0
			continue
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		var statusErr *APIStatusError
		if errors.As(err, &statusErr) && statusErr.Status == http.StatusUnauthorized {
			c.tokens.Invalidate()
		}

		if handled {
			reconnectAttempt = 0
		} else {
			reconnectAttempt++
		}
		delay := retryDelay(defaultRetryPolicy, reconnectAttempt)
		c.logger.Warn().Err(err).Dur("retry_in", delay).Msg("Event Streams connection ended; reconnecting")
		if err := waitForRetry(ctx, delay); err != nil {
			return err
		}
	}
}

func (c *EventStreamsClient) consumeOnce(ctx context.Context, handle EventHandler) (bool, error) {
	d, err := c.discover(ctx)
	if err != nil {
		return false, err
	}
	feedsCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	type result struct {
		handled bool
		err     error
	}
	results := make(chan result, len(d.Resources))
	for _, feed := range d.Resources {
		feed := feed
		go func() { handled, err := c.consumeFeed(feedsCtx, feed, handle); results <- result{handled, err} }()
	}
	first := <-results
	cancel()
	handled := first.handled
	feedErr := first.err
	refresh := errors.Is(first.err, errSessionRefresh)
	for i := 1; i < len(d.Resources); i++ {
		r := <-results
		handled = handled || r.handled
		if errors.Is(r.err, errSessionRefresh) {
			refresh = true
		}
		if feedErr == nil && r.err != nil && !errors.Is(r.err, context.Canceled) {
			feedErr = r.err
		}
	}
	if ctx.Err() != nil {
		return handled, ctx.Err()
	}
	if refresh {
		return handled, errSessionRefresh
	}
	return handled, feedErr
}

func (c *EventStreamsClient) consumeFeed(ctx context.Context, feed feedResource, handle EventHandler) (bool, error) {
	feedToken := feed.SessionToken.Token
	if feedToken == "" {
		feedToken = feed.Token.Token
	}
	if feed.DataFeedURL == "" || feedToken == "" {
		return false, fmt.Errorf("event streams discover returned an incomplete feed resource")
	}

	sessionCtx, cancelSession := context.WithCancel(ctx)
	defer cancelSession()

	refreshFired := make(chan struct{})
	var timer *time.Timer
	if refreshAfter := sessionRefreshAfter(feed.RefreshActiveSessionInterval); refreshAfter > 0 {
		timer = time.NewTimer(refreshAfter)
		defer timer.Stop()
		go func() {
			select {
			case <-timer.C:
				close(refreshFired)
				cancelSession()
			case <-sessionCtx.Done():
			}
		}()
	}

	resp, err := c.connectFeed(sessionCtx, feed.DataFeedURL, feedToken)
	if err != nil {
		select {
		case <-refreshFired:
			return false, errSessionRefresh
		default:
			return false, err
		}
	}
	defer resp.Body.Close()
	c.logger.Info().Msg("connected to Event Streams data feed")

	handled := false
	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 0, 64*1024), 10*1024*1024) // allow large individual events
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		ev, err := parseEventStreamLine(line)
		if err != nil {
			c.logger.Warn().Err(err).Msg("skipping unparsable Event Streams line")
			continue
		}
		if err := handle(ev); err != nil {
			return handled, fmt.Errorf("handling Event Streams event: %w", err)
		}
		handled = true
	}

	select {
	case <-refreshFired:
		return handled, errSessionRefresh
	default:
	}
	if err := scanner.Err(); err != nil {
		return handled, fmt.Errorf("reading Event Streams data feed: %w", err)
	}
	return handled, errStreamClosed
}

func (c *EventStreamsClient) connectFeed(ctx context.Context, dataFeedURL, feedToken string) (*http.Response, error) {
	var result *http.Response
	err := retry(ctx, c.breaker, defaultRetryPolicy, func() error {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, dataFeedURL, nil)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Token "+feedToken)

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return fmt.Errorf("connecting to Event Streams data feed: %w", err)
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return &APIStatusError{Operation: "Event Streams data feed", Status: resp.StatusCode}
		}
		result = resp
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func sessionRefreshAfter(intervalSeconds int) time.Duration {
	if intervalSeconds <= 0 {
		return 0
	}
	interval := time.Duration(intervalSeconds) * time.Second
	// Renew a little early to avoid racing session expiry, while retaining a
	// one-second minimum for unexpectedly small values.
	refresh := interval * 9 / 10
	if refresh < time.Second {
		return time.Second
	}
	return refresh
}

func parseEventStreamLine(line string) (models.Event, error) {
	var raw map[string]any
	if err := json.Unmarshal([]byte(line), &raw); err != nil {
		return models.Event{}, err
	}

	ev := models.Event{
		Source:     models.SourceEventStreams,
		IngestedAt: time.Now().UTC(),
		OccurredAt: time.Now().UTC(),
		RawPayload: []byte(line),
		Raw:        raw,
	}

	// CrowdStrike wraps the real payload under "metadata"/"event" in most
	// Event Streams messages. Pull out the commonly useful fields defensively,
	// but keep the full raw payload regardless so nothing is lost.
	if meta, ok := raw["metadata"].(map[string]any); ok {
		if et, ok := meta["eventType"].(string); ok {
			ev.EventType = et
		}
		if ts, ok := meta["eventCreationTime"].(float64); ok {
			ev.OccurredAt = time.UnixMilli(int64(ts)).UTC()
		}
	}
	if event, ok := raw["event"].(map[string]any); ok {
		if aid, ok := event["AgentId"].(string); ok {
			ev.AID = aid
		}
		if host, ok := event["Hostname"].(string); ok {
			ev.Hostname = host
		}
		// Detection summaries use a numeric Severity score and a human-readable
		// SeverityName (High/Medium/Low). Prefer the name for Wazuh rules.
		if sev, ok := event["SeverityName"].(string); ok && strings.TrimSpace(sev) != "" {
			ev.Severity = strings.TrimSpace(sev)
		} else if sev, ok := event["Severity"].(string); ok {
			ev.Severity = strings.TrimSpace(sev)
		}
		if tactic, ok := event["Tactic"].(string); ok {
			ev.Tactic = tactic
		}
		if tech, ok := event["Technique"].(string); ok {
			ev.Technique = tech
		}
	}

	return ev, nil
}
