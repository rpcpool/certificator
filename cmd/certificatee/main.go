package main

import (
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"text/tabwriter"
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
	// Parse subcommand
	args := os.Args[1:]
	cmd := "sync" // default command

	if len(args) > 0 && args[0] != "" && args[0][0] != '-' {
		cmd = args[0]
		args = args[1:]
	}

	switch cmd {
	case "sync":
		syncCmd(args)
	case "list-certs":
		listCertsCmd(args)
	case "help", "-h", "--help":
		printUsage()
		os.Exit(0)
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", cmd)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("Usage: certificatee [command] [options]")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  sync         Run the certificate sync daemon (default)")
	fmt.Println("  list-certs   List certificates from HAProxy instances")
	fmt.Println("  help         Show this help message")
	fmt.Println()
	fmt.Println("Options for list-certs:")
	fmt.Println("  -v, --verbose    Show detailed certificate information")
}

func syncCmd(_ []string) {
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

func listCertsCmd(args []string) {
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

	// Check for verbose flag
	verbose := false
	for _, arg := range args {
		if arg == "-v" || arg == "--verbose" {
			verbose = true
			break
		}
	}

	haproxyClients, err := createHAProxyClients(cfg, logger)
	if err != nil {
		logger.Fatal(err)
	}

	// Process each HAProxy endpoint
	for _, client := range haproxyClients {
		if err := listCertificates(client, verbose); err != nil {
			logger.Errorf("Failed to list certificates from %s: %v", client.Endpoint(), err)
		}
	}
}

func createHAProxyClients(cfg config.Config, logger *logrus.Logger) ([]*haproxy.Client, error) {
	var clientConfigs []haproxy.ClientConfig
	for _, url := range cfg.Certificatee.HAProxyDataPlaneAPIURLs {
		clientConfigs = append(clientConfigs, haproxy.ClientConfig{
			BaseURL:            url,
			Username:           cfg.Certificatee.HAProxyDataPlaneAPIUser,
			Password:           cfg.Certificatee.HAProxyDataPlaneAPIPassword,
			InsecureSkipVerify: cfg.Certificatee.HAProxyDataPlaneAPIInsecure,
		})
	}

	return haproxy.NewClients(clientConfigs, logger)
}

func listCertificates(client *haproxy.Client, verbose bool) error {
	endpoint := client.Endpoint()
	fmt.Printf("\n=== Certificates on %s ===\n\n", endpoint)

	if verbose {
		// Use ListCertificateRefs for verbose mode to get both display names and file paths
		certRefs, err := client.ListCertificateRefs()
		if err != nil {
			return fmt.Errorf("failed to list certificates: %w", err)
		}

		if len(certRefs) == 0 {
			fmt.Println("No certificates found.")
			return nil
		}

		// Show detailed info for each certificate
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		_, _ = fmt.Fprintln(w, "NAME\tSUBJECT\tISSUER\tNOT BEFORE\tNOT AFTER\tSERIAL")
		_, _ = fmt.Fprintln(w, "----\t-------\t------\t----------\t---------\t------")

		for _, ref := range certRefs {
			info, err := client.GetCertificateInfoByRef(ref)
			if err != nil {
				_, _ = fmt.Fprintf(w, "%s\t<error: %v>\t\t\t\t\n", ref.DisplayName, err)
				continue
			}

			notBefore := formatTime(info.NotBefore)
			notAfter := formatTime(info.NotAfter)

			_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
				ref.DisplayName,
				truncate(info.Subject, 30),
				truncate(info.Issuer, 30),
				notBefore,
				notAfter,
				info.Serial,
			)
		}
		_ = w.Flush()
		fmt.Printf("\nTotal: %d certificate(s)\n", len(certRefs))
	} else {
		// Simple list
		certPaths, err := client.ListCertificates()
		if err != nil {
			return fmt.Errorf("failed to list certificates: %w", err)
		}

		if len(certPaths) == 0 {
			fmt.Println("No certificates found.")
			return nil
		}

		for _, certPath := range certPaths {
			fmt.Println(certPath)
		}
		fmt.Printf("\nTotal: %d certificate(s)\n", len(certPaths))
	}

	return nil
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return "N/A"
	}
	return t.Format("2006-01-02")
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
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

		// Get certificate info from HAProxy using the file path
		haproxyCertInfo, err := haproxyClient.GetCertificateInfoByRef(ref)
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to get certificate info for %s: %w", certPath, err))
			logger.Errorf("[%s] %v", endpoint, err)
			continue
		}

		// Extract domain name from certificate path
		domain := haproxy.ExtractDomainFromPath(certPath)
		logger.Debugf("[%s] Extracted domain '%s' from path '%s'", endpoint, domain, certPath)

		// Track expiring certificates
		if haproxy.IsExpiring(haproxyCertInfo, cfg.Certificatee.RenewBeforeDays) {
			expiringCount++
		}

		// Check if certificate needs update
		shouldUpdate, reason, err := shouldUpdateCertificate(logger, haproxyCertInfo, domain, vaultClient, cfg.Certificatee.RenewBeforeDays)
		if err != nil {
			errs = append(errs, err)
			logger.Errorf("[%s] %v", endpoint, err)
			continue
		}

		if shouldUpdate {
			logger.Infof("[%s] Certificate %s needs update: %s", endpoint, certPath, reason)

			if err := updateCertificate(logger, certPath, domain, vaultClient, haproxyClient); err != nil {
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

func shouldUpdateCertificate(logger *logrus.Logger, haproxyCertInfo *haproxy.CertInfo, domain string, vaultClient *vault.VaultClient, renewBeforeDays int) (bool, string, error) {
	// Get certificate from Vault
	vaultCert, err := certificate.GetCertificate(domain, vaultClient)
	if err != nil {
		return false, "", fmt.Errorf("failed to get certificate %s from vault: %w", domain, err)
	}

	if vaultCert == nil {
		return false, "", fmt.Errorf("certificate for %s does not exist in vault", domain)
	}

	// Check if HAProxy certificate is expiring
	if haproxy.IsExpiring(haproxyCertInfo, renewBeforeDays) {
		return true, fmt.Sprintf("certificate expires on %s (within %d days)", haproxyCertInfo.NotAfter.Format(time.RFC3339), renewBeforeDays), nil
	}

	// Compare serial numbers
	if serialsDiffer(haproxyCertInfo, vaultCert) {
		return true, fmt.Sprintf("serial mismatch: HAProxy=%s, Vault=%s",
			haproxyCertInfo.Serial, formatSerial(vaultCert.SerialNumber.Bytes())), nil
	}

	return false, "", nil
}

// serialsDiffer compares the serial numbers of HAProxy and Vault certificates
func serialsDiffer(haproxyCertInfo *haproxy.CertInfo, vaultCert *x509.Certificate) bool {
	if haproxyCertInfo == nil || vaultCert == nil {
		return true
	}

	haproxySerial := haproxy.NormalizeSerial(haproxyCertInfo.Serial)
	vaultSerial := haproxy.NormalizeSerial(formatSerial(vaultCert.SerialNumber.Bytes()))

	return haproxySerial != vaultSerial
}

// formatSerial converts a certificate serial number to hex string
func formatSerial(serial []byte) string {
	return hex.EncodeToString(serial)
}

func updateCertificate(logger *logrus.Logger, certPath, domain string, vaultClient *vault.VaultClient, haproxyClient *haproxy.Client) error {
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
func buildPEMBundle(secrets map[string]interface{}) (string, error) {
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
