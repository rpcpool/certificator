package main

import (
	"context"
	"errors"
	"fmt"

	"github.com/vinted/certificator/pkg/haproxy"
	"github.com/vinted/certificator/pkg/vault"
)

func newCertificateeHealthChecker(vaultClient *vault.VaultClient, haproxyClients []*haproxy.Client) func(context.Context) error {
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
				if haproxy.IsV3UnavailableError(err) {
					continue
				}
				errs = append(errs, fmt.Errorf("%s: %w", client.Endpoint(), err))
			}
		}

		return errors.Join(errs...)
	}
}
