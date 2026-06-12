package main

import (
	"context"
	"fmt"
	"sync"
	"time"
)

const certificateeHealthStartupGrace = 2 * time.Minute

type vaultTokenChecker interface {
	TokenLookupSelf() error
}

type certificateeHealthChecker struct {
	vaultClient  vaultTokenChecker
	now          func() time.Time
	startedAt    time.Time
	startupGrace time.Duration
	maxSyncAge   time.Duration

	mu                 sync.RWMutex
	lastSuccessfulSync time.Time
}

func newCertificateeHealthChecker(vaultClient vaultTokenChecker, updateInterval time.Duration) *certificateeHealthChecker {
	now := time.Now
	return &certificateeHealthChecker{
		vaultClient:  vaultClient,
		now:          now,
		startedAt:    now(),
		startupGrace: certificateeHealthStartupGrace,
		maxSyncAge:   certificateeHealthMaxSyncAge(updateInterval),
	}
}

func certificateeHealthMaxSyncAge(updateInterval time.Duration) time.Duration {
	maxAge := updateInterval*2 + time.Minute
	if maxAge < certificateeHealthStartupGrace {
		return certificateeHealthStartupGrace
	}
	return maxAge
}

func (h *certificateeHealthChecker) Check(ctx context.Context) error {
	if h == nil {
		return nil
	}

	if err := ctx.Err(); err != nil {
		return err
	}

	if h.vaultClient != nil {
		if err := h.vaultClient.TokenLookupSelf(); err != nil {
			return err
		}
	}

	now := h.now()
	lastSuccessfulSync := h.lastSync()
	if !lastSuccessfulSync.IsZero() {
		if now.Sub(lastSuccessfulSync) <= h.maxSyncAge {
			return nil
		}

		return fmt.Errorf("no HAProxy Data Plane API v3 endpoint has completed a successful runtime certificate API probe since %s", lastSuccessfulSync.Format(time.RFC3339))
	}

	if now.Sub(h.startedAt) <= h.startupGrace {
		return nil
	}

	return fmt.Errorf("no HAProxy Data Plane API v3 endpoint has completed a successful runtime certificate API probe")
}

func (h *certificateeHealthChecker) MarkEndpointSyncSuccess() {
	if h == nil {
		return
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	h.lastSuccessfulSync = h.now()
}

func (h *certificateeHealthChecker) lastSync() time.Time {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.lastSuccessfulSync
}
