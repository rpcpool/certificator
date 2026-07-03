package main

import (
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
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

type certificateStore interface {
	KVRead(path string) (map[string]any, error)
}

type certificateSyncResult struct {
	isExpiring     bool
	storageSynced  bool
	runtimeUpdated bool
	reason         string
}

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

	healthChecker := newCertificateeHealthChecker(vaultClient, cfg.Certificatee.UpdateInterval)
	certmetrics.StartMetricsServer(logger, cfg.Metrics.ListenAddress, healthChecker.Check)
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
	if err := maybeUpdateCertificates(logger, cfg, vaultClient, haproxyClients, healthChecker); err != nil {
		logger.Error(err)
	}

	for range ticker.C {
		if err := maybeUpdateCertificates(logger, cfg, vaultClient, haproxyClients, healthChecker); err != nil {
			logger.Error(err)
		}
	}
}

func maybeUpdateCertificates(logger *logrus.Logger, cfg config.Config, vaultClient certificateStore, haproxyClients []*haproxy.Client, healthChecker *certificateeHealthChecker) error {
	var allErrs []error

	for _, haproxyClient := range haproxyClients {
		endpoint := haproxyClient.Endpoint()
		logger.Infof("Processing HAProxy endpoint: %s", endpoint)

		if err := processHAProxyEndpoint(logger, cfg, vaultClient, haproxyClient, healthChecker); err != nil {
			allErrs = append(allErrs, fmt.Errorf("endpoint %s: %w", endpoint, err))
			logger.Errorf("Failed to process endpoint %s: %v", endpoint, err)
		}
	}

	return errors.Join(allErrs...)
}

func processHAProxyEndpoint(logger *logrus.Logger, cfg config.Config, vaultClient certificateStore, haproxyClient *haproxy.Client, healthChecker *certificateeHealthChecker) error {
	endpoint := haproxyClient.Endpoint()

	certRefs, err := haproxyClient.ListCertificateRefs()
	if err != nil {
		if haproxy.IsHTTPStatus(err, http.StatusNotFound) {
			setDataPlaneAPIVersion(endpoint, "v2")
			// Do not cache this state. Endpoints can be upgraded independently,
			// so every sync run probes the v3 runtime certificate API again.
			logger.Warnf("[%s] HAProxy Data Plane API does not expose the v3 runtime SSL certificate API; skipping endpoint this run: %v", endpoint, err)
			return nil
		}

		setDataPlaneAPIVersion(endpoint, "")
		return err
	}

	// Mark endpoint as up and record sync timestamp
	setDataPlaneAPIVersion(endpoint, "v3")
	healthChecker.MarkEndpointSyncSuccess()
	certmetrics.LastSyncTimestamp.WithLabelValues(endpoint).SetToCurrentTime()
	certmetrics.CertificatesTotal.WithLabelValues(endpoint).Set(float64(len(certRefs)))

	var wildcardCount int
	for _, ref := range certRefs {
		if strings.Contains(ref.DisplayName, "*") || strings.Contains(ref.APIName, "*") {
			wildcardCount++
		}
	}
	certmetrics.CertificatesWildcard.WithLabelValues(endpoint).Set(float64(wildcardCount))

	logger.Infof("[%s] %d certificates found (%d with wildcard names)", endpoint, len(certRefs), wildcardCount)

	var errs []error
	var expiringCount int

	for _, ref := range certRefs {
		displayName := ref.DisplayName
		apiName := ref.APIName
		logger.Infof("[%s] Checking certificate: %s", endpoint, displayName)

		// Extract domain name from certificate path and normalize _.domain → *.domain for Vault
		rawDomain := haproxy.ExtractDomainFromPath(displayName)
		domain := haproxy.NormalizeDomainForVault(rawDomain)
		logger.Debugf("[%s] Extracted domain '%s' from certificate '%s'", endpoint, domain, displayName)

		haproxyCert, err := haproxyClient.GetCertificateDetail(apiName)
		if err != nil {
			certmetrics.CertificateMetadataLookupFailures.WithLabelValues(endpoint, domain).Inc()
			errs = append(errs, err)
			logger.Errorf("[%s] failed to get live dataplane metadata for %s: %v", endpoint, displayName, err)
			continue
		}

		if haproxyCert != nil && !haproxyCert.NotAfter.IsZero() {
			certmetrics.CertificateNotAfterTimestamp.WithLabelValues(endpoint, domain).Set(float64(haproxyCert.NotAfter.Unix()))
		}

		// Use HAProxy's live certificate metadata for expiry. Vault provides the
		// replacement payload persisted to storage and, when needed, runtime.
		syncResult, err := syncCertificate(apiName, domain, vaultClient, haproxyClient, haproxyCert, cfg.Certificatee.RenewBeforeDays)

		// Track expiring certificates even when Vault replacement material is invalid.
		if syncResult.isExpiring {
			expiringCount++
		}

		if err != nil {
			errs = append(errs, err)
			logger.Errorf("[%s] %v", endpoint, err)
			certmetrics.CertificatesUpdateFailures.WithLabelValues(endpoint, domain).Inc()
			continue
		}

		if syncResult.storageSynced {
			logger.Infof("[%s] Certificate %s persisted to storage", endpoint, displayName)
		}

		if syncResult.runtimeUpdated {
			certmetrics.CertificatesUpdated.WithLabelValues(endpoint, domain).Inc()
			logger.Infof("[%s] Certificate %s updated successfully: %s", endpoint, displayName, syncResult.reason)
			continue
		}

		logger.Infof("[%s] Certificate %s is up to date", endpoint, displayName)
	}

	// Record expiring certificates count
	certmetrics.CertificatesExpiring.WithLabelValues(endpoint).Set(float64(expiringCount))

	return errors.Join(errs...)
}

func setDataPlaneAPIVersion(endpoint, version string) {
	for _, candidate := range []string{"v2", "v3"} {
		value := 0.0
		if version == candidate {
			value = 1
		}
		certmetrics.DataPlaneAPIVersion.WithLabelValues(endpoint, candidate).Set(value)
	}
}

func shouldUpdateForLiveExpiry(domain string, haproxyCert *haproxy.CertificateDetail, renewBeforeDays int) (shouldUpdate bool, reason string, isExpiring bool, err error) {
	if haproxyCert == nil {
		return false, "", false, fmt.Errorf("live certificate metadata for %s is unavailable", domain)
	}

	if haproxyCert.NotAfter.IsZero() {
		return false, "", false, fmt.Errorf("certificate %s is missing not_after in live haproxy metadata", domain)
	}

	threshold := time.Now().AddDate(0, 0, renewBeforeDays)
	isExpiring = haproxyCert.NotAfter.Before(threshold)
	if isExpiring {
		return true, fmt.Sprintf("live haproxy certificate expires on %s (within %d days)", haproxyCert.NotAfter.Format(time.RFC3339), renewBeforeDays), true, nil
	}

	return false, "", false, nil
}

func shouldUpdateForSerialMismatch(vaultCert *x509.Certificate, haproxyCert *haproxy.CertificateDetail) (bool, string) {
	vaultSerial := haproxy.NormalizeSerial(vaultCert.SerialNumber.Text(16))
	haproxySerial := haproxy.NormalizeSerial(haproxyCert.Serial)
	if haproxySerial != "" && vaultSerial != haproxySerial {
		return true, fmt.Sprintf("serial mismatch: vault=%s haproxy=%s", vaultSerial, haproxySerial)
	}

	return false, ""
}

func validateVaultCertificateForUpdate(domain string, vaultCert *x509.Certificate, haproxyCert *haproxy.CertificateDetail) error {
	return validateVaultCertificateForUpdateAt(domain, vaultCert, haproxyCert, time.Now())
}

func validateVaultCertificateForUpdateAt(domain string, vaultCert *x509.Certificate, haproxyCert *haproxy.CertificateDetail, now time.Time) error {
	if vaultCert == nil {
		return fmt.Errorf("certificate for %s does not exist in vault", domain)
	}

	if vaultCert.IsCA {
		return fmt.Errorf("refusing to update %s: Vault certificate bundle starts with a CA certificate", domain)
	}

	if certificate.IsExpired(vaultCert, now) {
		return fmt.Errorf("refusing to update %s: Vault certificate expired on %s", domain, vaultCert.NotAfter.Format(time.RFC3339))
	}

	if haproxyCert != nil && !haproxyCert.NotAfter.IsZero() && vaultCert.NotAfter.Before(haproxyCert.NotAfter) {
		return fmt.Errorf("refusing to update %s: Vault certificate expires on %s before live HAProxy certificate expires on %s", domain, vaultCert.NotAfter.Format(time.RFC3339), haproxyCert.NotAfter.Format(time.RFC3339))
	}

	return nil
}

func parseVaultLeafCertificate(secrets map[string]any) (*x509.Certificate, error) {
	certPEM, ok := secrets["certificate"].(string)
	if !ok || certPEM == "" {
		return nil, fmt.Errorf("certificate not found in vault secrets")
	}

	return certificate.ParsePEMCertificate(certPEM)
}

func readVaultCertificateBundle(domain string, vaultClient certificateStore) (map[string]any, *x509.Certificate, error) {
	certificateSecrets, err := vaultClient.KVRead(certificate.VaultCertLocation(domain))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read certificate data from vault for %s: %w", domain, err)
	}

	vaultCert, err := parseVaultLeafCertificate(certificateSecrets)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse Vault certificate for %s: %w", domain, err)
	}

	return certificateSecrets, vaultCert, nil
}

func syncCertificate(certPath, domain string, vaultClient certificateStore, haproxyClient *haproxy.Client, haproxyCert *haproxy.CertificateDetail, renewBeforeDays int) (certificateSyncResult, error) {
	result := certificateSyncResult{}

	shouldUpdateRuntime, reason, isExpiring, err := shouldUpdateForLiveExpiry(domain, haproxyCert, renewBeforeDays)
	result.isExpiring = isExpiring
	if err != nil {
		return result, err
	}

	certificateSecrets, vaultCert, err := readVaultCertificateBundle(domain, vaultClient)
	if err != nil {
		return result, err
	}

	if err := validateVaultCertificateForUpdate(domain, vaultCert, haproxyCert); err != nil {
		return result, err
	}

	pemData, err := buildPEMBundle(certificateSecrets)
	if err != nil {
		return result, fmt.Errorf("failed to build PEM bundle for %s: %w", domain, err)
	}

	storageCertName := haproxy.StorageCertificateName(certPath)
	if err := haproxyClient.EnsureStorageCertificate(storageCertName, pemData); err != nil {
		return result, fmt.Errorf("failed to persist certificate %s in HAProxy storage: %w", storageCertName, err)
	}
	result.storageSynced = true

	if !shouldUpdateRuntime {
		shouldUpdateRuntime, reason = shouldUpdateForSerialMismatch(vaultCert, haproxyCert)
	}

	if !shouldUpdateRuntime {
		return result, nil
	}

	result.reason = reason

	if err := haproxyClient.UpdateCertificate(certPath, pemData); err != nil {
		return result, fmt.Errorf("failed to update certificate %s in HAProxy runtime: %w", certPath, err)
	}

	result.runtimeUpdated = true
	return result, nil
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
