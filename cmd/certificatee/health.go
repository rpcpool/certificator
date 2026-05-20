package main

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/vinted/certificator/pkg/haproxy"
	"github.com/vinted/certificator/pkg/vault"
)

type syncHealthState struct {
	mu              sync.RWMutex
	lastSuccess     time.Time
	lastFailure     time.Time
	lastFailureText string
}

func (s *syncHealthState) Mark(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err == nil {
		s.lastSuccess = time.Now()
		s.lastFailureText = ""
		return
	}

	s.lastFailure = time.Now()
	s.lastFailureText = err.Error()
}

func (s *syncHealthState) Check(maxAge time.Duration) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.lastSuccess.IsZero() {
		if s.lastFailureText != "" {
			return fmt.Errorf("initial sync has not succeeded yet: %s", s.lastFailureText)
		}
		return fmt.Errorf("initial sync has not succeeded yet")
	}

	if time.Since(s.lastSuccess) > maxAge {
		if s.lastFailureText != "" {
			return fmt.Errorf("last successful sync is stale (%s ago): %s", time.Since(s.lastSuccess).Round(time.Second), s.lastFailureText)
		}
		return fmt.Errorf("last successful sync is stale (%s ago)", time.Since(s.lastSuccess).Round(time.Second))
	}

	return nil
}

func newCertificateeHealthChecker(vaultClient *vault.VaultClient, haproxyClients []*haproxy.Client, state *syncHealthState, updateInterval time.Duration) func(context.Context) error {
	maxSyncAge := updateInterval * 2
	if maxSyncAge < time.Minute {
		maxSyncAge = time.Minute
	}

	return func(ctx context.Context) error {
		if err := vaultClient.TokenLookupSelf(); err != nil {
			return err
		}

		var errs []error
		for _, client := range haproxyClients {
			if err := ctx.Err(); err != nil {
				return err
			}

			if _, err := client.ListCertificateRefs(); err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", client.Endpoint(), err))
			}
		}

		if err := state.Check(maxSyncAge); err != nil {
			errs = append(errs, err)
		}

		return errors.Join(errs...)
	}
}
