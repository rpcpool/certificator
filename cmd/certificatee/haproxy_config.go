package main

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/vinted/certificator/pkg/haproxy"
)

func sanitizeWildcardCertName(name string) string {
	name = strings.ReplaceAll(name, "*", "_")
	name = strings.ReplaceAll(name, "..", ".")
	return name
}

func ensureStorageCertificate(haproxyClient *haproxy.Client, certName, pemData string) error {
	refs, err := haproxyClient.ListCertificateRefs()
	if err != nil {
		return err
	}

	normalized := normalizeCertificateName(certName)
	for _, ref := range refs {
		if certRefMatches(ref, certName) || certRefMatches(ref, normalized) {
			if err := haproxyClient.UpdateCertificate(certName, pemData); err == nil {
				return nil
			}
			break
		}
	}

	if err := haproxyClient.CreateCertificate(certName, pemData); err != nil {
		// Data Plane API normalizes storage names (e.g., replaces '*' and other chars with '_'),
		// so a create may return 409 even if the exact requested name wasn't found above.
		if strings.Contains(err.Error(), "already exists") {
			if err := haproxyClient.UpdateCertificate(certName, pemData); err == nil {
				return nil
			}
		}
		return fmt.Errorf("failed to create certificate %s: %w", certName, err)
	}
	return nil
}

func normalizeCertificateName(name string) string {
	builder := strings.Builder{}
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' || r == '.' {
			builder.WriteRune(r)
		} else {
			builder.WriteRune('_')
		}
	}
	return builder.String()
}

func certRefMatches(ref haproxy.CertificateRef, name string) bool {
	if ref.DisplayName == name {
		return true
	}
	if ref.FilePath == name {
		return true
	}
	return filepath.Base(ref.FilePath) == name
}
