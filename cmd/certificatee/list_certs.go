package main

import (
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	legoLog "github.com/go-acme/lego/v4/log"
	"github.com/vinted/certificator/pkg/config"
	"github.com/vinted/certificator/pkg/haproxy"
)

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
