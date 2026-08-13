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
	storageSynced  bool
	runtimeUpdated bool
	reason         string
	skipReason     string
}

// processedCertificateOutcome records what happened to one certificate ref
// during this sync cycle, so legacy-duplicate cleanup can tell whether the
// certificate it would keep is confirmed healthy.
type processedCertificateOutcome struct {
	ref    haproxy.CertificateRef
	domain string
	err    error
	result certificateSyncResult
}

// isStable reports whether this cycle's sync needed no corrective action for
// this certificate: no error, nothing skipped, and no fresh runtime push.
func (o processedCertificateOutcome) isStable() bool {
	return o.err == nil && o.result.skipReason == "" && !o.result.runtimeUpdated
}

// certRefDetail is a certificate ref together with the live HAProxy metadata
// fetched for it this cycle. Fetching every ref's detail before any writes
// happen lets legacy-duplicate classification see every ref's live SAN up
// front, instead of discovering duplicates mid-loop after some may already
// have been synced.
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

	// Phase 1: fetch every ref's live metadata before doing any writes, so
	// legacy-duplicate classification (which needs every ref's live SAN) sees
	// the whole picture up front instead of discovering a duplicate mid-loop
	// after one half of the pair has already been synced.
	details := make([]certRefDetail, 0, len(certRefs))
	for _, ref := range certRefs {
		fallbackDomain := domainFromCertificateName(ref.DisplayName)

		haproxyCert, err := haproxyClient.GetCertificateDetail(ref.APIName)
		if err != nil {
			certmetrics.CertificateMetadataLookupFailures.WithLabelValues(endpoint, fallbackDomain).Inc()
			errs = append(errs, err)
			logger.Errorf("[%s] failed to get live dataplane metadata for %s: %v", endpoint, ref.DisplayName, err)
			continue
		}

		details = append(details, certRefDetail{ref: ref, haproxyCert: haproxyCert, fallbackDomain: fallbackDomain})
	}

	legacyKeeperAPIName := classifyLegacyDuplicates(logger, endpoint, details)

	// Phase 2: sync every ref that isn't a confirmed legacy duplicate, exactly
	// as before. Confirmed legacy duplicates are handled in phase 3 instead,
	// once we know whether their keeper turned out stable this cycle.
	outcomes := make(map[string]processedCertificateOutcome, len(details))
	for _, d := range details {
		if _, isLegacy := legacyKeeperAPIName[d.ref.APIName]; isLegacy {
			continue
		}
		outcomes[d.ref.APIName] = syncOneCertificate(logger, cfg, vaultClient, haproxyClient, endpoint, d, &errs, &expiringCount, &skippedVaultCount)
	}

	// Phase 3: for each confirmed legacy duplicate, remove it once its keeper
	// is confirmed healthy this cycle. If the keeper isn't stable yet, keep
	// maintaining the duplicate normally rather than risk an unrenewed
	// certificate - cleanup can wait for a calmer cycle.
	for _, d := range details {
		keeperAPIName, isLegacy := legacyKeeperAPIName[d.ref.APIName]
		if !isLegacy {
			continue
		}

		keeperOutcome, ok := outcomes[keeperAPIName]
		if !ok || !keeperOutcome.isStable() {
			outcomes[d.ref.APIName] = syncOneCertificate(logger, cfg, vaultClient, haproxyClient, endpoint, d, &errs, &expiringCount, &skippedVaultCount)
			continue
		}

		removeLegacyDuplicateCertificate(logger, endpoint, haproxyClient, d.ref, keeperOutcome.domain)
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
) processedCertificateOutcome {
	ref := d.ref
	displayName := ref.DisplayName
	apiName := ref.APIName
	haproxyCert := d.haproxyCert

	logger.Infof("[%s] Checking certificate: %s", endpoint, displayName)

	candidateDomains := domainsForVault(displayName, haproxyCert)
	logger.Debugf("[%s] Candidate Vault domains for certificate '%s': %s", endpoint, displayName, strings.Join(candidateDomains, ", "))

	// Use HAProxy's live certificate metadata for expiry. Vault provides the
	// replacement payload persisted to storage and, when needed, runtime.
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
		return processedCertificateOutcome{ref: ref, domain: domain, err: err, result: syncResult}
	}

	if syncResult.skipReason != "" {
		*skippedVaultCount++
		logger.Debugf("[%s] Skipping certificate %s: %s", endpoint, displayName, syncResult.skipReason)
		return processedCertificateOutcome{ref: ref, domain: domain, result: syncResult}
	}

	if syncResult.storageSynced {
		logger.Infof("[%s] Certificate %s persisted to storage", endpoint, displayName)
	}

	if syncResult.runtimeUpdated {
		certmetrics.CertificatesUpdated.WithLabelValues(endpoint, domain).Inc()
		logger.Infof("[%s] Certificate %s updated successfully: %s", endpoint, displayName, syncResult.reason)
		return processedCertificateOutcome{ref: ref, domain: domain, result: syncResult}
	}

	logger.Infof("[%s] Certificate %s is up to date", endpoint, displayName)
	return processedCertificateOutcome{ref: ref, domain: domain, result: syncResult}
}

// isLegacyCertificateName reports whether displayName uses the pre-migration
// naming convention, where every "." in the domain (including the leading
// wildcard "*.") was sanitized to "_" (e.g. "__devnet_rpcpool_com.pem" or
// "api_mainnet-beta_solana_com.pem"). The current convention only sanitizes
// the leading "*." to "_." and otherwise keeps the domain's dots literal
// (e.g. "_.devnet.rpcpool.com.pem"), so a real domain name with zero dots
// after stripping the extension can only be the legacy encoding.
func isLegacyCertificateName(displayName string) bool {
	return !strings.Contains(haproxy.ExtractDomainFromPath(displayName), ".")
}

// classifyLegacyDuplicates groups refs by live SAN and, for any group of two
// or more, decides whether it resolves unambiguously to one current-format
// certificate (the keeper) and one or more legacy-named duplicates. It
// returns a map from a legacy duplicate's APIName to its keeper's APIName.
// Ambiguous groups (no keeper, or more than one) are logged and left alone
// rather than guessed at.
func classifyLegacyDuplicates(logger *logrus.Logger, endpoint string, details []certRefDetail) map[string]string {
	groups := make(map[string][]certRefDetail)
	for _, d := range details {
		san := certificateDomains(d.haproxyCert)
		if len(san) == 0 {
			continue
		}
		key := strings.Join(san, ",")
		groups[key] = append(groups[key], d)
	}

	legacyKeeperAPIName := make(map[string]string)
	for san, group := range groups {
		if len(group) < 2 {
			continue
		}

		var keeper *certRefDetail
		var legacy []certRefDetail
		ambiguous := false

		for i := range group {
			d := group[i]
			if isLegacyCertificateName(d.ref.DisplayName) {
				legacy = append(legacy, d)
				continue
			}
			if keeper != nil {
				ambiguous = true
				continue
			}
			keeper = &group[i]
		}

		if ambiguous || keeper == nil || len(legacy) == 0 {
			logger.Warnf("[%s] %d certificate(s) share SAN %q but do not resolve to exactly one current-format certificate and one or more legacy duplicates; skipping cleanup", endpoint, len(group), san)
			continue
		}

		for _, l := range legacy {
			legacyKeeperAPIName[l.ref.APIName] = keeper.ref.APIName
		}
	}

	return legacyKeeperAPIName
}

// removeLegacyDuplicateCertificate deletes a confirmed legacy duplicate's
// storage file. Runtime-level deletion isn't viable here: HAProxy refuses to
// remove a certificate still referenced by a bind ("del ssl cert" returns a
// 500 "in use" error), which every file loaded from a directory crt-store is,
// regardless of whether it's the one actually selected for a live SNI match.
// Storage deletion (skip_reload=true) does succeed and removes the on-disk
// file for good, but HAProxy's live runtime listing is intentionally
// disconnected from disk state without a reload, so the deleted name keeps
// reappearing in ListCertificateRefs until some later reload happens for
// unrelated reasons - at which point it drops out on its own. Until then,
// repeating this delete is a harmless no-op (or a 404): the caller is
// responsible for never handing this ref back through the normal sync path
// once it's classified as a legacy duplicate, or the delete and the ordinary
// sync's storage write would fight each other every cycle.
func removeLegacyDuplicateCertificate(logger *logrus.Logger, endpoint string, haproxyClient *haproxy.Client, ref haproxy.CertificateRef, keeperDomain string) {
	storageCertName := haproxy.StorageCertificateName(ref.APIName)
	if err := haproxyClient.DeleteCertificate(storageCertName); err != nil {
		if haproxy.IsHTTPStatus(err, http.StatusNotFound) {
			return
		}
		certmetrics.LegacyCertificatesRemovalFailures.WithLabelValues(endpoint, keeperDomain).Inc()
		logger.Warnf("[%s] failed to remove legacy duplicate certificate %s: %v", endpoint, ref.DisplayName, err)
		return
	}

	certmetrics.LegacyCertificatesRemoved.WithLabelValues(endpoint, keeperDomain).Inc()
	logger.Infof("[%s] Removed legacy duplicate certificate %s from storage (HAProxy will drop it from its live listing on the next reload)", endpoint, ref.DisplayName)
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
