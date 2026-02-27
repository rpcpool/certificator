package main

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	legoLog "github.com/go-acme/lego/v4/log"
	"github.com/sirupsen/logrus"
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

	var certSource CertSource
	if cfg.Certificatee.LocalCertsDir != "" {
		certSource = LocalCertSource{dir: cfg.Certificatee.LocalCertsDir}
		logger.Warnf("Using local certificate directory: %s", cfg.Certificatee.LocalCertsDir)
	} else {
		vaultClient, err := vault.NewVaultClient(cfg.Vault.ApproleRoleID,
			cfg.Vault.ApproleSecretID, cfg.Environment, cfg.Vault.KVStoragePath, logger)
		if err != nil {
			logger.Fatal(err)
		}
		certSource = VaultCertSource{client: vaultClient}
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
	if err := maybeUpdateCertificates(logger, cfg, certSource, haproxyClients); err != nil {
		logger.Error(err)
	}

	for range ticker.C {
		if err := maybeUpdateCertificates(logger, cfg, certSource, haproxyClients); err != nil {
			logger.Error(err)
		}
	}
}

func maybeUpdateCertificates(logger *logrus.Logger, cfg config.Config, certSource CertSource, haproxyClients []*haproxy.Client) error {
	var allErrs []error

	for _, haproxyClient := range haproxyClients {
		endpoint := haproxyClient.Endpoint()
		logger.Infof("Processing HAProxy endpoint: %s", endpoint)

		if err := processHAProxyEndpoint(logger, cfg, certSource, haproxyClient); err != nil {
			allErrs = append(allErrs, fmt.Errorf("endpoint %s: %w", endpoint, err))
			logger.Errorf("Failed to process endpoint %s: %v", endpoint, err)
		}
	}

	return errors.Join(allErrs...)
}

func processHAProxyEndpoint(logger *logrus.Logger, cfg config.Config, certSource CertSource, haproxyClient *haproxy.Client) error {
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
		if certPath == "" {
			certPath = filepath.Base(ref.FilePath)
		}
		logger.Infof("[%s] Checking certificate: %s", endpoint, certPath)

		// Extract domain name from certificate path
		domain := haproxy.ExtractDomainFromPath(certPath)
		logger.Debugf("[%s] Extracted domain '%s' from path '%s'", endpoint, domain, certPath)

		// Check if certificate needs update (uses certificate source as truth for cert details,
		// since HAProxy Data Plane API doesn't provide certificate metadata)
		shouldUpdate, reason, isExpiring, err := shouldUpdateCertificate(domain, certSource, cfg.Certificatee.RenewBeforeDays)
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

			if err := updateCertificate(ref, domain, certSource, haproxyClient); err != nil {
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

func shouldUpdateCertificate(domain string, certSource CertSource, renewBeforeDays int) (shouldUpdate bool, reason string, isExpiring bool, err error) {
	// Get certificate from source - this is the source of truth for certificate details
	// (HAProxy Data Plane API doesn't provide certificate metadata like expiry or serial)
	vaultCert, err := certSource.GetCertificate(domain)
	if err != nil {
		return false, "", false, fmt.Errorf("failed to get certificate %s from source: %w", domain, err)
	}

	if vaultCert == nil {
		return false, "", false, fmt.Errorf("certificate for %s does not exist in source", domain)
	}

	// Check if Vault certificate is expiring
	threshold := time.Now().AddDate(0, 0, renewBeforeDays)
	isExpiring = vaultCert.NotAfter.Before(threshold)

	if isExpiring {
		// Certificate is expiring, sync to HAProxy (likely was recently renewed)
		return true, fmt.Sprintf("certificate expires on %s (within %d days)", vaultCert.NotAfter.Format(time.RFC3339), renewBeforeDays), true, nil
	}

	return false, "", false, nil
}

func updateCertificate(ref haproxy.CertificateRef, domain string, certSource CertSource, haproxyClient *haproxy.Client) error {
	// Build PEM bundle (certificate + private key)
	pemData, err := certSource.GetPEMBundle(domain)
	if err != nil {
		return fmt.Errorf("failed to load PEM bundle for %s: %w", domain, err)
	}

	certName := ref.DisplayName
	if certName == "" {
		certName = filepath.Base(ref.FilePath)
	}

	if strings.Contains(certName, "*") || strings.Contains(ref.FilePath, "*") {
		if err := ensureStorageCertificate(haproxyClient, sanitizeWildcardCertName(certName), pemData); err != nil {
			return err
		}
		return nil
	}

	// Update certificate in HAProxy (storage API)
	if err := haproxyClient.UpdateCertificate(certName, pemData); err != nil {
		return fmt.Errorf("failed to update certificate %s in HAProxy: %w", certName, err)
	}

	return nil
}

// endsWith checks if a string ends with a suffix
func endsWith(s, suffix string) bool {
	if len(s) < len(suffix) {
		return false
	}
	return s[len(s)-len(suffix):] == suffix
}
