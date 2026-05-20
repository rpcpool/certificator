package main

import (
	"errors"
	"fmt"
	"strings"
	"time"

	legoLog "github.com/go-acme/lego/v4/log"
	"github.com/sirupsen/logrus"
	"github.com/vinted/certificator/pkg/certificate"
	"github.com/vinted/certificator/pkg/certmetrics"
	"github.com/vinted/certificator/pkg/config"
	"github.com/vinted/certificator/pkg/haproxy"
	"github.com/vinted/certificator/pkg/vault"
)

var (
	version = "dev" // GoReleaser will inject the Git tag here
)

func main() {
	cfg, err := config.LoadConfig()
	if err != nil {
		cfg.Log.Logger.Fatal(err)
	}

	logger := cfg.Log.Logger
	legoLog.Logger = logger

	// Validate HAProxy Data Plane API configuration
	if len(cfg.Certificatee.HAProxyDataPlaneAPIURLs) == 0 {
		logger.Fatal("HAPROXY_DATAPLANE_API_URLS must be set (comma-separated list of Data Plane API URLs)")
	}

	vaultClient, err := vault.NewVaultClient(cfg.Vault.ApproleRoleID,
		cfg.Vault.ApproleSecretID, cfg.Environment, cfg.Vault.KVStoragePath, logger)
	if err != nil {
		logger.Fatal(err)
	}

	haproxyClients, err := createHAProxyClients(cfg, logger)
	if err != nil {
		logger.Fatal(err)
	}

	certmetrics.StartMetricsServer(logger, cfg.Metrics.ListenAddress, newCertificateeHealthChecker(vaultClient, haproxyClients))
	defer certmetrics.PushMetrics(logger, cfg.Metrics.PushUrl)

	logger.Infof("Configured %d HAProxy endpoint(s)", len(haproxyClients))
	for _, client := range haproxyClients {
		logger.Infof("  - %s", client.Endpoint())
	}

	ticker := time.NewTicker(cfg.Certificatee.UpdateInterval)
	defer ticker.Stop()

	certmetrics.Up.WithLabelValues("certificatee", version, cfg.Hostname, cfg.Environment).Set(1)
	defer certmetrics.Up.WithLabelValues("certificatee", version, cfg.Hostname, cfg.Environment).Set(0)

	// Initial run
	if err := maybeUpdateCertificates(logger, cfg, vaultClient, haproxyClients); err != nil {
		logger.Error(err)
	}

	for range ticker.C {
		if err := maybeUpdateCertificates(logger, cfg, vaultClient, haproxyClients); err != nil {
			logger.Error(err)
		}
	}
}

func maybeUpdateCertificates(logger *logrus.Logger, cfg config.Config, vaultClient *vault.VaultClient, haproxyClients []*haproxy.Client) error {
	var allErrs []error

	for _, haproxyClient := range haproxyClients {
		endpoint := haproxyClient.Endpoint()
		logger.Infof("Processing HAProxy endpoint: %s", endpoint)

		if err := processHAProxyEndpoint(logger, cfg, vaultClient, haproxyClient); err != nil {
			allErrs = append(allErrs, fmt.Errorf("endpoint %s: %w", endpoint, err))
			logger.Errorf("Failed to process endpoint %s: %v", endpoint, err)
		}
	}

	return errors.Join(allErrs...)
}

func processHAProxyEndpoint(logger *logrus.Logger, cfg config.Config, vaultClient *vault.VaultClient, haproxyClient *haproxy.Client) error {
	endpoint := haproxyClient.Endpoint()

	// Get list of certificates from HAProxy with file paths for lookups
	certRefs, err := haproxyClient.ListCertificateRefs()
	if err != nil {
		if haproxy.IsV3UnavailableError(err) {
			certmetrics.HAProxyEndpointUp.WithLabelValues(endpoint).Set(1)
			certmetrics.HAProxyEndpointV3Ready.WithLabelValues(endpoint).Set(0)
			certmetrics.HAProxyEndpointWorking.WithLabelValues(endpoint).Set(0)
			logger.Infof("[%s] HAProxy Data Plane API v3 certificate storage endpoint not available yet, waiting for upgrade", endpoint)
			return nil
		}

		certmetrics.HAProxyEndpointUp.WithLabelValues(endpoint).Set(0)
		certmetrics.HAProxyEndpointV3Ready.WithLabelValues(endpoint).Set(0)
		certmetrics.HAProxyEndpointWorking.WithLabelValues(endpoint).Set(0)
		return fmt.Errorf("failed to list certificates: %w", err)
	}

	// Mark endpoint as up and record sync timestamp
	certmetrics.HAProxyEndpointUp.WithLabelValues(endpoint).Set(1)
	certmetrics.HAProxyEndpointV3Ready.WithLabelValues(endpoint).Set(1)
	certmetrics.LastSyncTimestamp.WithLabelValues(endpoint).SetToCurrentTime()
	certmetrics.CertificatesTotal.WithLabelValues(endpoint).Set(float64(len(certRefs)))

	var wildcardCount int
	for _, ref := range certRefs {
		if strings.Contains(ref.DisplayName, "*") || strings.Contains(ref.FilePath, "*") {
			wildcardCount++
		}
	}
	certmetrics.CertificatesWildcard.WithLabelValues(endpoint).Set(float64(wildcardCount))

	logger.Infof("[%s] %d certificates found (%d with wildcard names)", endpoint, len(certRefs), wildcardCount)

	var errs []error
	var expiringCount int

	for _, ref := range certRefs {
		certPath := ref.DisplayName
		logger.Infof("[%s] Checking certificate: %s", endpoint, certPath)

		// Extract domain name from certificate path and normalize _.domain → *.domain for Vault
		rawDomain := haproxy.ExtractDomainFromPath(certPath)
		domain := haproxy.NormalizeDomainForVault(rawDomain)
		logger.Debugf("[%s] Extracted domain '%s' from path '%s'", endpoint, domain, certPath)

		haproxyCert, err := haproxyClient.GetCertificateDetail(certPath)
		if err != nil {
			certmetrics.CertificateMetadataLookupFailures.WithLabelValues(endpoint, domain).Inc()

			if strings.Contains(err.Error(), "status 404") {
				logger.Warnf("[%s] missing dataplane metadata for %s, falling back to vault expiry only: %v", endpoint, certPath, err)
				haproxyCert = nil
			} else {
				errs = append(errs, err)
				logger.Errorf("[%s] failed to get dataplane metadata for %s: %v", endpoint, certPath, err)
				continue
			}
		}

		if haproxyCert != nil && !haproxyCert.NotAfter.IsZero() {
			certmetrics.CertificateNotAfterTimestamp.WithLabelValues(endpoint, domain).Set(float64(haproxyCert.NotAfter.Unix()))
		}

		// Use Vault as the source of truth and HAProxy Data Plane API v3 metadata as
		// the source of the currently loaded certificate state.
		shouldUpdate, reason, isExpiring, err := shouldUpdateCertificate(domain, vaultClient, haproxyCert, cfg.Certificatee.RenewBeforeDays)
		if err != nil {
			errs = append(errs, err)
			logger.Errorf("[%s] %v", endpoint, err)
			continue
		}

		// Track expiring certificates
		if isExpiring {
			expiringCount++
		}

		if shouldUpdate {
			logger.Infof("[%s] Certificate %s needs update: %s", endpoint, certPath, reason)

			if err := updateCertificate(certPath, domain, vaultClient, haproxyClient); err != nil {
				errs = append(errs, err)
				logger.Errorf("[%s] %v", endpoint, err)
				certmetrics.CertificatesUpdateFailures.WithLabelValues(endpoint, domain).Inc()
			} else {
				certmetrics.CertificatesUpdated.WithLabelValues(endpoint, domain).Inc()
				logger.Infof("[%s] Certificate %s updated successfully!", endpoint, certPath)
			}
		} else {
			logger.Infof("[%s] Certificate %s is up to date", endpoint, certPath)
		}
	}

	// Record expiring certificates count
	certmetrics.CertificatesExpiring.WithLabelValues(endpoint).Set(float64(expiringCount))
	if len(errs) == 0 {
		certmetrics.HAProxyEndpointWorking.WithLabelValues(endpoint).Set(1)
	} else {
		certmetrics.HAProxyEndpointWorking.WithLabelValues(endpoint).Set(0)
	}

	return errors.Join(errs...)
}

func shouldUpdateCertificate(domain string, vaultClient *vault.VaultClient, haproxyCert *haproxy.CertificateDetail, renewBeforeDays int) (shouldUpdate bool, reason string, isExpiring bool, err error) {
	vaultCert, err := certificate.GetCertificate(domain, vaultClient)
	if err != nil {
		return false, "", false, fmt.Errorf("failed to get certificate %s from vault: %w", domain, err)
	}

	if vaultCert == nil {
		return false, "", false, fmt.Errorf("certificate for %s does not exist in vault", domain)
	}

	if haproxyCert == nil {
		threshold := time.Now().AddDate(0, 0, renewBeforeDays)
		isExpiring = vaultCert.NotAfter.Before(threshold)
		if isExpiring {
			return true, fmt.Sprintf("vault certificate expires on %s (haproxy metadata unavailable)", vaultCert.NotAfter.Format(time.RFC3339)), true, nil
		}
		return false, "", false, nil
	}

	if haproxyCert.NotAfter.IsZero() {
		return false, "", false, fmt.Errorf("certificate %s is missing not_after in haproxy metadata", domain)
	}

	threshold := time.Now().AddDate(0, 0, renewBeforeDays)
	isExpiring = haproxyCert.NotAfter.Before(threshold)

	if isExpiring {
		return true, fmt.Sprintf("haproxy certificate expires on %s (within %d days)", haproxyCert.NotAfter.Format(time.RFC3339), renewBeforeDays), true, nil
	}

	vaultSerial := haproxy.NormalizeSerial(vaultCert.SerialNumber.Text(16))
	haproxySerial := haproxy.NormalizeSerial(haproxyCert.Serial)
	if haproxySerial != "" && vaultSerial != haproxySerial {
		return true, fmt.Sprintf("serial mismatch: vault=%s haproxy=%s", vaultSerial, haproxySerial), false, nil
	}

	if vaultCert.NotAfter.After(haproxyCert.NotAfter) {
		return true, fmt.Sprintf("vault certificate is newer: vault=%s haproxy=%s", vaultCert.NotAfter.Format(time.RFC3339), haproxyCert.NotAfter.Format(time.RFC3339)), false, nil
	}

	return false, "", false, nil
}

func updateCertificate(certPath, domain string, vaultClient *vault.VaultClient, haproxyClient *haproxy.Client) error {
	// Read certificate data from Vault
	certificateSecrets, err := vaultClient.KVRead(certificate.VaultCertLocation(domain))
	if err != nil {
		return fmt.Errorf("failed to read certificate data from vault for %s: %w", domain, err)
	}

	// Build PEM bundle (certificate + private key)
	pemData, err := buildPEMBundle(certificateSecrets)
	if err != nil {
		return fmt.Errorf("failed to build PEM bundle for %s: %w", domain, err)
	}

	// Update certificate in HAProxy
	if err := haproxyClient.UpdateCertificate(certPath, pemData); err != nil {
		return fmt.Errorf("failed to update certificate %s in HAProxy: %w", certPath, err)
	}

	return nil
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

// endsWith checks if a string ends with a suffix
func endsWith(s, suffix string) bool {
	if len(s) < len(suffix) {
		return false
	}
	return s[len(s)-len(suffix):] == suffix
}
