package crowdstrike

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// TokenSource handles CrowdStrike's OAuth2 client-credentials flow and
// transparently refreshes the token before it expires. Safe for concurrent use.
type TokenSource struct {
	baseURL      string
	clientID     string
	clientSecret string
	httpClient   *http.Client
	breaker      *CircuitBreaker

	mu        sync.Mutex
	token     string
	expiresAt time.Time
}

func NewTokenSource(baseURL, clientID, clientSecret string) *TokenSource {
	return &TokenSource{
		baseURL:      strings.TrimRight(baseURL, "/"),
		clientID:     clientID,
		clientSecret: clientSecret,
		httpClient:   &http.Client{Timeout: 15 * time.Second},
		breaker:      NewCircuitBreaker(3, 30*time.Second),
	}
}

// Token returns a valid bearer token, refreshing it if it's missing or about
// to expire (CrowdStrike tokens are short-lived, typically 30 minutes).
func (t *TokenSource) Token(ctx context.Context) (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.token != "" && time.Now().Before(t.expiresAt.Add(-60*time.Second)) {
		return t.token, nil
	}

	var token string
	var expiresIn int
	err := retry(ctx, t.breaker, defaultRetryPolicy, func() error {
		var err error
		token, expiresIn, err = t.requestToken(ctx)
		return err
	})
	if err != nil {
		return "", fmt.Errorf("refreshing OAuth2 token: %w", err)
	}

	t.token = token
	t.expiresAt = time.Now().Add(time.Duration(expiresIn) * time.Second)
	return t.token, nil
}

// Invalidate causes the next Token call to obtain a new token. It is used when
// Event Streams requires a periodic active-session refresh.
func (t *TokenSource) Invalidate() {
	t.mu.Lock()
	t.token = ""
	t.expiresAt = time.Time{}
	t.mu.Unlock()
}

func (t *TokenSource) requestToken(ctx context.Context) (string, int, error) {
	form := url.Values{}
	form.Set("client_id", t.clientID)
	form.Set("client_secret", t.clientSecret)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.baseURL+"/oauth2/token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := t.httpClient.Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("oauth2 token request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return "", 0, &APIStatusError{Operation: "oauth2 token request", Status: resp.StatusCode}
	}

	var body struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", 0, fmt.Errorf("decoding oauth2 response: %w", err)
	}
	if body.AccessToken == "" || body.ExpiresIn <= 0 {
		return "", 0, fmt.Errorf("oauth2 response did not contain a usable access token")
	}
	return body.AccessToken, body.ExpiresIn, nil
}
