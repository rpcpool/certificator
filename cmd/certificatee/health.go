package main

import (
	"context"

	"github.com/vinted/certificator/pkg/vault"
)

func newCertificateeHealthChecker(vaultClient *vault.VaultClient) func(context.Context) error {
	return func(ctx context.Context) error {
		if err := ctx.Err(); err != nil {
			return err
		}

		if err := vaultClient.TokenLookupSelf(); err != nil {
			return err
		}
		return nil
	}
}
