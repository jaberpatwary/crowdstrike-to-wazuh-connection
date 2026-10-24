package crowdstrike

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"sync"
	"time"
)

// RetryPolicy bounds retries for calls to CrowdStrike. It is deliberately
// conservative: a caller gets at most four attempts before the error is
// returned to its consumer loop.
type RetryPolicy struct {
	Attempts     int
	InitialDelay time.Duration
	MaxDelay     time.Duration
}

var defaultRetryPolicy = RetryPolicy{
	Attempts:     4,
	InitialDelay: 250 * time.Millisecond,
	MaxDelay:     10 * time.Second,
}

// CircuitBreaker stops repeated failed request cycles from hammering an
// unavailable service. A successful request closes it; after a cool-down one
// request is allowed through to check whether the service has recovered.
type CircuitBreaker struct {
	mu        sync.Mutex
	failures  int
	threshold int
	cooldown  time.Duration
	openedAt  time.Time
	open      bool
	probe     bool
}

func NewCircuitBreaker(threshold int, cooldown time.Duration) *CircuitBreaker {
	return &CircuitBreaker{threshold: threshold, cooldown: cooldown}
}

func (b *CircuitBreaker) Allow(now time.Time) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if !b.open {
		return nil
	}
	if remaining := b.cooldown - now.Sub(b.openedAt); remaining > 0 {
		return &CircuitOpenError{RetryAfter: remaining}
	}
	if b.probe {
		return &CircuitOpenError{RetryAfter: time.Second}
	}
	b.probe = true
	return nil
}

func (b *CircuitBreaker) RecordSuccess() {
	b.mu.Lock()
	b.failures = 0
	b.open = false
	b.probe = false
	b.openedAt = time.Time{}
	b.mu.Unlock()
}

func (b *CircuitBreaker) RecordFailure(now time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.probe = false
	b.failures++
	if b.failures >= b.threshold {
		b.open = true
		b.openedAt = now
	}
}

type CircuitOpenError struct {
	RetryAfter time.Duration
}

func (e *CircuitOpenError) Error() string {
	return fmt.Sprintf("CrowdStrike circuit breaker is open; retry after %s", e.RetryAfter.Round(time.Millisecond))
}

// RetryableError marks an error as safe to retry. HTTP status errors implement
// it for timeouts, rate limits, and server-side failures.
type RetryableError interface {
	Retryable() bool
}

// APIStatusError carries a non-success response without retaining a response
// body, which could contain sensitive information.
type APIStatusError struct {
	Operation string
	Status    int
}

func (e *APIStatusError) Error() string {
	return fmt.Sprintf("%s returned status %d", e.Operation, e.Status)
}

func (e *APIStatusError) Retryable() bool {
	return e.Status == 408 || e.Status == 429 || e.Status >= 500
}

func retry(ctx context.Context, breaker *CircuitBreaker, policy RetryPolicy, operation func() error) error {
	if err := breaker.Allow(time.Now()); err != nil {
		return err
	}

	var lastErr error
	for attempt := 0; attempt < policy.Attempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}

		err := operation()
		if err == nil {
			breaker.RecordSuccess()
			return nil
		}
		lastErr = err
		if !isRetryable(err) || attempt == policy.Attempts-1 {
			break
		}

		if err := waitForRetry(ctx, retryDelay(policy, attempt)); err != nil {
			return err
		}
	}

	breaker.RecordFailure(time.Now())
	return lastErr
}

func isRetryable(err error) bool {
	var marked RetryableError
	if errors.As(err, &marked) {
		return marked.Retryable()
	}
	// Network errors from net/http do not implement RetryableError. Context
	// cancellation and deadline expiry are never retried.
	return !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded)
}

func waitForRetry(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func retryDelay(policy RetryPolicy, attempt int) time.Duration {
	delay := policy.InitialDelay
	for i := 0; i < attempt && delay < policy.MaxDelay; i++ {
		delay *= 2
	}
	if delay > policy.MaxDelay {
		delay = policy.MaxDelay
	}

	// Full jitter spreads reconnecting replicas across the interval. Keep a
	// small floor so immediate retry loops cannot occur.
	minimum := delay / 2
	return minimum + time.Duration(rand.Int63n(int64(delay-minimum)+1))
}
