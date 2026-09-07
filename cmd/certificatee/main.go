package main

import (
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"slices"
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

	errNoUsableVaultCertificate = errors.New("no usable Vault certificate")
)

type certificateStore interface {
	KVRead(path string) (map[string]any, error)
}

type certificateSyncResult struct {
	domain         string
	isExpiring     bool
	runtimeUpdated bool
	reason         string
	skipReason     string
}

// certRefDetail is a certificate ref together with the live HAProxy metadata
// fetched for it this cycle.
type certRefDetail struct {
	ref            haproxy.CertificateRef
	haproxyCert    *haproxy.CertificateDetail
	fallbackDomain string
}

type noUsableVaultCertificateError struct {
	domains []string
	cause   error
}

func (e *noUsableVaultCertificateError) Error() string {
	return fmt.Sprintf("no usable Vault certificate found for candidates %s: %v", strings.Join(e.domains, ", "), e.cause)
}

func (e *noUsableVaultCertificateError) Unwrap() []error {
	return []error{errNoUsableVaultCertificate, e.cause}
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
	var skippedVaultCount int

	for _, ref := range certRefs {
		fallbackDomain := domainFromCertificateName(ref.DisplayName)

		haproxyCert, err := haproxyClient.GetCertificateDetail(ref.APIName)
		if err != nil {
			certmetrics.CertificateMetadataLookupFailures.WithLabelValues(endpoint, fallbackDomain).Inc()
			errs = append(errs, err)
			logger.Errorf("[%s] failed to get live dataplane metadata for %s: %v", endpoint, ref.DisplayName, err)
			continue
		}

		d := certRefDetail{ref: ref, haproxyCert: haproxyCert, fallbackDomain: fallbackDomain}
		syncOneCertificate(logger, cfg, vaultClient, haproxyClient, endpoint, d, &errs, &expiringCount, &skippedVaultCount)
	}

	// Record expiring certificates count
	certmetrics.CertificatesExpiring.WithLabelValues(endpoint).Set(float64(expiringCount))
	if skippedVaultCount > 0 {
		logger.Infof("[%s] Skipped %d certificate(s) without usable Vault replacement material", endpoint, skippedVaultCount)
	}

	return errors.Join(errs...)
}

// syncOneCertificate runs the normal Vault-to-HAProxy sync for a single
// certificate ref and returns its outcome. Shared by the main sync pass and
// the legacy-duplicate fallback path, so both go through identical logic.
func syncOneCertificate(
	logger *logrus.Logger,
	cfg config.Config,
	vaultClient certificateStore,
	haproxyClient *haproxy.Client,
	endpoint string,
	d certRefDetail,
	errs *[]error,
	expiringCount *int,
	skippedVaultCount *int,
) {
	ref := d.ref
	displayName := ref.DisplayName
	apiName := ref.APIName
	haproxyCert := d.haproxyCert

	logger.Infof("[%s] Checking certificate: %s", endpoint, displayName)

	candidateDomains := domainsForVault(displayName, haproxyCert)
	logger.Debugf("[%s] Candidate Vault domains for certificate '%s': %s", endpoint, displayName, strings.Join(candidateDomains, ", "))

	// Use HAProxy's live certificate metadata for expiry. Vault provides the
	// replacement payload pushed to the HAProxy runtime when needed.
	syncResult, err := syncCertificate(apiName, candidateDomains, vaultClient, haproxyClient, haproxyCert, cfg.Certificatee.RenewBeforeDays)
	domain := syncResult.domain
	if domain == "" {
		domain = d.fallbackDomain
	}

	if haproxyCert != nil && !haproxyCert.NotAfter.IsZero() {
		certmetrics.CertificateNotAfterTimestamp.WithLabelValues(endpoint, domain).Set(float64(haproxyCert.NotAfter.Unix()))
	}

	// Track expiring certificates even when Vault replacement material is invalid.
	if syncResult.isExpiring {
		*expiringCount++
	}

	if err != nil {
		*errs = append(*errs, err)
		logger.Errorf("[%s] %v", endpoint, err)
		certmetrics.CertificatesUpdateFailures.WithLabelValues(endpoint, domain).Inc()
		return
	}

	if syncResult.skipReason != "" {
		*skippedVaultCount++
		logger.Debugf("[%s] Skipping certificate %s: %s", endpoint, displayName, syncResult.skipReason)
		return
	}

	if syncResult.runtimeUpdated {
		certmetrics.CertificatesUpdated.WithLabelValues(endpoint, domain).Inc()
		logger.Infof("[%s] Certificate %s updated successfully: %s", endpoint, displayName, syncResult.reason)
		return
	}

	logger.Infof("[%s] Certificate %s is up to date", endpoint, displayName)
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

func domainFromCertificateName(displayName string) string {
	rawDomain := haproxy.ExtractDomainFromPath(displayName)
	return haproxy.NormalizeDomainForVault(rawDomain)
}

func domainsForVault(displayName string, haproxyCert *haproxy.CertificateDetail) []string {
	seen := make(map[string]struct{})
	domains := make([]string, 0, 1)
	candidates := append(certificateDomains(haproxyCert), domainFromCertificateName(displayName))

	for _, candidate := range candidates {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" {
			continue
		}
		if _, ok := seen[candidate]; ok {
			continue
		}

		seen[candidate] = struct{}{}
		domains = append(domains, candidate)
	}

	return domains
}

func certificateDomains(haproxyCert *haproxy.CertificateDetail) []string {
	if haproxyCert == nil {
		return nil
	}

	return parseCertificateDomainList(haproxyCert.Domains, haproxyCert.SubjectAlternativeNames)
}

func parseCertificateDomainList(values ...string) []string {
	seen := make(map[string]struct{})
	var domains []string

	for _, value := range values {
		for _, candidate := range strings.Split(value, ",") {
			candidate = strings.TrimSpace(candidate)
			if candidate == "" {
				continue
			}

			if strings.HasPrefix(candidate, "DNS:") || strings.HasPrefix(candidate, "dns:") {
				candidate = strings.TrimSpace(candidate[4:])
			} else if strings.Contains(candidate, ":") {
				continue
			}

			if candidate == "" {
				continue
			}
			if _, ok := seen[candidate]; ok {
				continue
			}

			seen[candidate] = struct{}{}
			domains = append(domains, candidate)
		}
	}

	return domains
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

	expectedDomains := expectedVaultCertificateDomains(domain, haproxyCert)
	if !vaultCertificateMatchesDomains(vaultCert, expectedDomains) {
		return fmt.Errorf("refusing to update %s: Vault certificate DNS names %v do not match live HAProxy DNS names %v", domain, vaultCert.DNSNames, expectedDomains)
	}

	if haproxyCert != nil && !haproxyCert.NotAfter.IsZero() && vaultCert.NotAfter.Before(haproxyCert.NotAfter) {
		return fmt.Errorf("refusing to update %s: Vault certificate expires on %s before live HAProxy certificate expires on %s", domain, vaultCert.NotAfter.Format(time.RFC3339), haproxyCert.NotAfter.Format(time.RFC3339))
	}

	return nil
}

func expectedVaultCertificateDomains(domain string, haproxyCert *haproxy.CertificateDetail) []string {
	domains := certificateDomains(haproxyCert)
	if len(domains) > 0 {
		return domains
	}

	if domain == "" {
		return nil
	}

	return []string{domain}
}

func vaultCertificateMatchesDomains(vaultCert *x509.Certificate, domains []string) bool {
	if vaultCert == nil || len(vaultCert.DNSNames) != len(domains) {
		return false
	}

	vaultDomains := append([]string(nil), vaultCert.DNSNames...)
	expectedDomains := append([]string(nil), domains...)
	slices.Sort(vaultDomains)
	slices.Sort(expectedDomains)

	return slices.Equal(vaultDomains, expectedDomains)
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

func readValidVaultCertificateBundle(domains []string, vaultClient certificateStore, haproxyCert *haproxy.CertificateDetail) (string, map[string]any, *x509.Certificate, error) {
	var errs []error

	for _, domain := range domains {
		certificateSecrets, vaultCert, err := readVaultCertificateBundle(domain, vaultClient)
		if err != nil {
			errs = append(errs, err)
			continue
		}

		if err := validateVaultCertificateForUpdate(domain, vaultCert, haproxyCert); err != nil {
			errs = append(errs, err)
			continue
		}

		return domain, certificateSecrets, vaultCert, nil
	}

	if len(domains) == 0 {
		return "", nil, nil, fmt.Errorf("no Vault certificate candidates found")
	}

	return "", nil, nil, &noUsableVaultCertificateError{
		domains: domains,
		cause:   errors.Join(errs...),
	}
}

func firstDomain(domains []string) string {
	if len(domains) == 0 {
		return ""
	}

	return domains[0]
}

func syncCertificate(certPath string, domains []string, vaultClient certificateStore, haproxyClient *haproxy.Client, haproxyCert *haproxy.CertificateDetail, renewBeforeDays int) (certificateSyncResult, error) {
	result := certificateSyncResult{domain: firstDomain(domains)}

	shouldUpdateRuntime, reason, isExpiring, err := shouldUpdateForLiveExpiry(result.domain, haproxyCert, renewBeforeDays)
	result.isExpiring = isExpiring
	if err != nil {
		return result, err
	}

	domain, certificateSecrets, vaultCert, err := readValidVaultCertificateBundle(domains, vaultClient, haproxyCert)
	if err != nil {
		if !isExpiring && errors.Is(err, errNoUsableVaultCertificate) {
			result.skipReason = err.Error()
			return result, nil
		}
		return result, err
	}
	result.domain = domain

	pemData, err := buildPEMBundle(certificateSecrets)
	if err != nil {
		return result, fmt.Errorf("failed to build PEM bundle for %s: %w", domain, err)
	}

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
