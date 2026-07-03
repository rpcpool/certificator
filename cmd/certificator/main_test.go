package main

import (
	"crypto/x509"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/vinted/certificator/pkg/certificate"
)

type recordingVaultDeleter struct {
	deletedPaths []string
	err          error
}

func (v *recordingVaultDeleter) KVDelete(path string) error {
	v.deletedPaths = append(v.deletedPaths, path)
	return v.err
}

func TestDeleteExpiredVaultCertificateAt(t *testing.T) {
	now := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
	logger := logrus.New()
	logger.SetOutput(io.Discard)

	t.Run("deletes expired certificate", func(t *testing.T) {
		vaultClient := &recordingVaultDeleter{}
		cert := &x509.Certificate{NotAfter: now.Add(-time.Second)}

		deleted, err := deleteExpiredVaultCertificateAt("example.com", cert, vaultClient, logger, now)
		if err != nil {
			t.Fatalf("deleteExpiredVaultCertificateAt() error = %v", err)
		}
		if !deleted {
			t.Fatal("deleteExpiredVaultCertificateAt() deleted = false, want true")
		}

		wantPath := certificate.VaultCertLocation("example.com")
		if len(vaultClient.deletedPaths) != 1 || vaultClient.deletedPaths[0] != wantPath {
			t.Fatalf("deleted paths = %v, want [%s]", vaultClient.deletedPaths, wantPath)
		}
	})

	t.Run("keeps valid certificate", func(t *testing.T) {
		vaultClient := &recordingVaultDeleter{}
		cert := &x509.Certificate{NotAfter: now.Add(time.Hour)}

		deleted, err := deleteExpiredVaultCertificateAt("example.com", cert, vaultClient, logger, now)
		if err != nil {
			t.Fatalf("deleteExpiredVaultCertificateAt() error = %v", err)
		}
		if deleted {
			t.Fatal("deleteExpiredVaultCertificateAt() deleted = true, want false")
		}
		if len(vaultClient.deletedPaths) != 0 {
			t.Fatalf("deleted paths = %v, want none", vaultClient.deletedPaths)
		}
	})

	t.Run("keeps missing certificate", func(t *testing.T) {
		vaultClient := &recordingVaultDeleter{}

		deleted, err := deleteExpiredVaultCertificateAt("example.com", nil, vaultClient, logger, now)
		if err != nil {
			t.Fatalf("deleteExpiredVaultCertificateAt() error = %v", err)
		}
		if deleted {
			t.Fatal("deleteExpiredVaultCertificateAt() deleted = true, want false")
		}
		if len(vaultClient.deletedPaths) != 0 {
			t.Fatalf("deleted paths = %v, want none", vaultClient.deletedPaths)
		}
	})

	t.Run("returns delete error", func(t *testing.T) {
		vaultClient := &recordingVaultDeleter{err: errors.New("vault delete failed")}
		cert := &x509.Certificate{NotAfter: now.Add(-time.Second)}

		deleted, err := deleteExpiredVaultCertificateAt("example.com", cert, vaultClient, logger, now)
		if err == nil {
			t.Fatal("deleteExpiredVaultCertificateAt() error = nil, want error")
		}
		if deleted {
			t.Fatal("deleteExpiredVaultCertificateAt() deleted = true, want false")
		}
		if !strings.Contains(err.Error(), "failed deleting expired Vault certificate for example.com") {
			t.Fatalf("error = %q, want domain context", err.Error())
		}

		wantPath := certificate.VaultCertLocation("example.com")
		if len(vaultClient.deletedPaths) != 1 || vaultClient.deletedPaths[0] != wantPath {
			t.Fatalf("deleted paths = %v, want [%s]", vaultClient.deletedPaths, wantPath)
		}
	})
}
