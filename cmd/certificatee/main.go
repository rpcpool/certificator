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

	certmetrics.StartMetricsServer(logger, cfg.Metrics.ListenAddress)
	defer certmetrics.PushMetrics(logger, cfg.Metrics.PushUrl)

	vaultClient, err := vault.NewVaultClient(cfg.Vault.ApproleRoleID,
		cfg.Vault.ApproleSecretID, cfg.Environment, cfg.Vault.KVStoragePath, logger)
	if err != nil {
		logger.Fatal(err)
	}

	haproxyClients, err := createHAProxyClients(cfg, logger)
	if err != nil {
		logger.Fatal(err)
	}

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
		certmetrics.HAProxyEndpointUp.WithLabelValues(endpoint).Set(0)
		return fmt.Errorf("failed to list certificates: %w", err)
	}

	// Mark endpoint as up and record sync timestamp
	certmetrics.HAProxyEndpointUp.WithLabelValues(endpoint).Set(1)
	certmetrics.LastSyncTimestamp.WithLabelValues(endpoint).SetToCurrentTime()
	certmetrics.CertificatesTotal.WithLabelValues(endpoint).Set(float64(len(certRefs)))

	logger.Infof("[%s] %d certificates found", endpoint, len(certRefs))

	var errs []error
	var expiringCount int

	for _, ref := range certRefs {
		certPath := ref.DisplayName
		logger.Infof("[%s] Checking certificate: %s", endpoint, certPath)

		// Support v3 advanced features: renaming certificates with '*' in filename
		if strings.Contains(certPath, "*") {
			if haproxyClient.APIVersion() >= 3 {
				newPath, err := renameCertificateWithWildcard(logger, certPath, haproxyClient)
				if err != nil {
					logger.Errorf("[%s] Failed to rename wildcard certificate %s: %v", endpoint, certPath, err)
				} else {
					certPath = newPath
				}
			} else if haproxyClient.APIVersion() < 2 {
				logger.Warnf("[%s] HAProxy Data Plane API v2 support isn't available. Please rename certificate %s manually to remove '*'.", endpoint, certPath)
			} else {
				logger.Warnf("[%s] Certificate %s contains '*', but automatic renaming requires HAProxy Data Plane API v3. Please rename manually.", endpoint, certPath)
			}
		}

		// Extract domain name from certificate path
		domain := haproxy.ExtractDomainFromPath(certPath)
		logger.Debugf("[%s] Extracted domain '%s' from path '%s'", endpoint, domain, certPath)

		// Check if certificate needs update
		shouldUpdate, reason, isExpiring, err := shouldUpdateCertificate(domain, vaultClient, cfg.Certificatee.RenewBeforeDays, haproxyClient, certPath, logger)
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

	return errors.Join(errs...)
}

func renameCertificateWithWildcard(logger *logrus.Logger, certPath string, haproxyClient *haproxy.Client) (string, error) {
	newCertPath := strings.ReplaceAll(certPath, "*", "_wildcard_")
	logger.Infof("Renaming wildcard certificate %s to %s", certPath, newCertPath)

	// 1. Get current PEM body
	pemData, err := haproxyClient.GetCertificateBody(certPath)
	if err != nil {
		return certPath, fmt.Errorf("failed to get certificate body for rename: %w", err)
	}

	// 2. Create new certificate (uploads to storage and runtime)
	if err := haproxyClient.CreateCertificate(newCertPath, pemData); err != nil {
		return certPath, fmt.Errorf("failed to create renamed certificate %s: %w", newCertPath, err)
	}

	// 3. Delete old certificate from storage (v3 feature)
	if err := haproxyClient.DeleteStorageCertificate(certPath); err != nil {
		logger.Errorf("Failed to delete old storage certificate %s after rename: %v", certPath, err)
	}

	// 4. Delete old certificate from runtime
	if err := haproxyClient.DeleteCertificate(certPath); err != nil {
		logger.Errorf("Failed to delete old runtime certificate %s after rename: %v", certPath, err)
	}

	return newCertPath, nil
}

func shouldUpdateCertificate(domain string, vaultClient *vault.VaultClient, renewBeforeDays int, haproxyClient *haproxy.Client, certPath string, logger *logrus.Logger) (shouldUpdate bool, reason string, isExpiring bool, err error) {
	// Get certificate from Vault - this is the source of truth for certificate details
	vaultCert, err := certificate.GetCertificate(domain, vaultClient)
	if err != nil {
		return false, "", false, fmt.Errorf("failed to get certificate %s from vault: %w", domain, err)
	}

	if vaultCert == nil {
		return false, "", false, fmt.Errorf("certificate for %s does not exist in vault", domain)
	}

	// Check if Vault certificate is expiring
	threshold := time.Now().AddDate(0, 0, renewBeforeDays)
	isExpiring = vaultCert.NotAfter.Before(threshold)

	// In v3, we can get the full certificate body from HAProxy to check its expiry and serial
	if haproxyClient.APIVersion() >= 3 {
		haproxyPem, err := haproxyClient.GetCertificateBody(certPath)
		if err == nil {
			// Parse HAProxy certificate
			haproxyCert, parseErr := certificate.ParsePEMCertificate(haproxyPem)
			if parseErr == nil {
				// 1. Check if HAProxy cert is expiring
				if haproxyCert.NotAfter.Before(threshold) {
					return true, fmt.Sprintf("HAProxy certificate expires on %s (within %d days)", haproxyCert.NotAfter.Format(time.RFC3339), renewBeforeDays), true, nil
				}

				// 2. Check if HAProxy cert differs from Vault cert (by serial number)
				if haproxy.NormalizeSerial(haproxyCert.SerialNumber.String()) != haproxy.NormalizeSerial(vaultCert.SerialNumber.String()) {
					return true, fmt.Sprintf("HAProxy certificate serial %s differs from Vault certificate serial %s",
						haproxyCert.SerialNumber.String(), vaultCert.SerialNumber.String()), false, nil
				}

				// HAProxy cert is up to date and valid
				return false, "", false, nil
			}
			logger.Warnf("Failed to parse HAProxy certificate %s: %v", certPath, parseErr)
		} else {
			logger.Warnf("Failed to get HAProxy certificate body for %s: %v", certPath, err)
		}
	}

	if isExpiring {
		// Certificate is expiring in Vault, sync to HAProxy
		return true, fmt.Sprintf("Vault certificate expires on %s (within %d days)", vaultCert.NotAfter.Format(time.RFC3339), renewBeforeDays), true, nil
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
