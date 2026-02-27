package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	"github.com/vinted/certificator/pkg/certificate"
	"github.com/vinted/certificator/pkg/vault"
)

type CertSource interface {
	GetCertificate(domain string) (*x509.Certificate, error)
	GetPEMBundle(domain string) (string, error)
}

type VaultCertSource struct {
	client *vault.VaultClient
}

func (v VaultCertSource) GetCertificate(domain string) (*x509.Certificate, error) {
	return certificate.GetCertificate(domain, v.client)
}

func (v VaultCertSource) GetPEMBundle(domain string) (string, error) {
	certificateSecrets, err := v.client.KVRead(certificate.VaultCertLocation(domain))
	if err != nil {
		return "", fmt.Errorf("failed to read certificate data from vault for %s: %w", domain, err)
	}

	pemData, err := buildPEMBundle(certificateSecrets)
	if err != nil {
		return "", fmt.Errorf("failed to build PEM bundle for %s: %w", domain, err)
	}

	return pemData, nil
}

type LocalCertSource struct {
	dir string
}

func (l LocalCertSource) GetCertificate(domain string) (*x509.Certificate, error) {
	data, err := os.ReadFile(l.certPath(domain))
	if err != nil {
		return nil, fmt.Errorf("failed to read local certificate for %s: %w", domain, err)
	}

	cert, err := parseCertificateFromPEM(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse local certificate for %s: %w", domain, err)
	}

	return cert, nil
}

func (l LocalCertSource) GetPEMBundle(domain string) (string, error) {
	data, err := os.ReadFile(l.certPath(domain))
	if err != nil {
		return "", fmt.Errorf("failed to read local PEM bundle for %s: %w", domain, err)
	}

	return string(data), nil
}

func (l LocalCertSource) certPath(domain string) string {
	return filepath.Join(l.dir, domain+".pem")
}

func parseCertificateFromPEM(pemData []byte) (*x509.Certificate, error) {
	rest := pemData
	for len(rest) > 0 {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		return cert, nil
	}

	return nil, fmt.Errorf("no certificate PEM block found")
}

// buildPEMBundle creates a PEM bundle from Vault certificate secrets
func buildPEMBundle(secrets map[string]any) (string, error) {
	var pemData string

	// Add certificate
	if cert, ok := secrets["certificate"].(string); ok && cert != "" {
		pemData += cert
	} else {
		return "", fmt.Errorf("certificate not found in vault secrets")
	}

	// Add newline between cert and key
	if !endsWith(pemData, "\n") {
		pemData += "\n"
	}

	// Add private key
	if key, ok := secrets["private_key"].(string); ok && key != "" {
		pemData += key
	} else {
		return "", fmt.Errorf("private_key not found in vault secrets")
	}

	return pemData, nil
}
