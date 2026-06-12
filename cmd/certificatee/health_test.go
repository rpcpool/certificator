package main

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

type fakeVaultTokenChecker struct {
	err error
}

func (f fakeVaultTokenChecker) TokenLookupSelf() error {
	return f.err
}

func TestCertificateeHealthCheckerRequiresRecentEndpointSync(t *testing.T) {
	start := time.Date(2026, 6, 12, 9, 0, 0, 0, time.UTC)
	now := start

	healthChecker := newCertificateeHealthChecker(fakeVaultTokenChecker{}, time.Minute)
	healthChecker.now = func() time.Time { return now }
	healthChecker.startedAt = start
	healthChecker.startupGrace = time.Second
	healthChecker.maxSyncAge = 2 * time.Second

	if err := healthChecker.Check(context.Background()); err != nil {
		t.Fatalf("Check() during startup grace error = %v, want nil", err)
	}

	now = start.Add(1500 * time.Millisecond)
	err := healthChecker.Check(context.Background())
	if err == nil || !strings.Contains(err.Error(), "no HAProxy Data Plane API v3 endpoint") {
		t.Fatalf("Check() after startup grace error = %v, want missing v3 endpoint sync", err)
	}

	healthChecker.MarkEndpointSyncSuccess()
	if err := healthChecker.Check(context.Background()); err != nil {
		t.Fatalf("Check() after sync success error = %v, want nil", err)
	}

	now = now.Add(3 * time.Second)
	err = healthChecker.Check(context.Background())
	if err == nil || !strings.Contains(err.Error(), "no HAProxy Data Plane API v3 endpoint") {
		t.Fatalf("Check() after stale sync error = %v, want stale v3 endpoint sync", err)
	}
}

func TestCertificateeHealthCheckerChecksVault(t *testing.T) {
	healthChecker := newCertificateeHealthChecker(fakeVaultTokenChecker{err: errors.New("vault unavailable")}, time.Minute)

	err := healthChecker.Check(context.Background())
	if err == nil || !strings.Contains(err.Error(), "vault unavailable") {
		t.Fatalf("Check() error = %v, want vault unavailable", err)
	}
}
