package main

import (
	"strings"

	legoLog "github.com/go-acme/lego/v4/log"
	"github.com/vinted/certificator/pkg/acme"
	"github.com/vinted/certificator/pkg/certificate"
	"github.com/vinted/certificator/pkg/certmetrics"
	"github.com/vinted/certificator/pkg/config"
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

	certmetrics.StartMetricsServer(logger, cfg.Metrics.ListenAddress)
	defer certmetrics.PushMetrics(logger, cfg.Metrics.PushUrl)

	vaultClient, err := vault.NewVaultClient(cfg.Vault.ApproleRoleID,
		cfg.Vault.ApproleSecretID, cfg.Environment, cfg.Vault.KVStoragePath, logger)
	if err != nil {
		logger.Fatal(err)
	}

	acmeClient, err := acme.NewClient(cfg.Acme.AccountEmail, cfg.Acme.ServerURL, cfg.Acme.EABKid, cfg.Acme.EABHmacKey,
		cfg.Acme.ReregisterAccount, vaultClient, logger)
	if err != nil {
		logger.Fatal(err)
	}

	certmetrics.Up.WithLabelValues("certificator", version, cfg.Hostname, cfg.Environment).Set(1)
	defer certmetrics.Up.WithLabelValues("certificator", version, cfg.Hostname, cfg.Environment).Set(0)

	var failedDomains []string

	for _, dom := range cfg.Domains {
		allDomains := strings.Split(dom, ",")
		mainDomain := allDomains[0]
		cert, err := certificate.GetCertificate(mainDomain, vaultClient)
		if err != nil {
			failedDomains = append(failedDomains, mainDomain)
			logger.Error(err)
			continue
		}
		logger.Infof("checking certificate for %s", mainDomain)

		needsReissuing, err := certificate.NeedsReissuing(cert, allDomains, cfg.RenewBeforeDays, logger)
		if err != nil {
			failedDomains = append(failedDomains, mainDomain)
			logger.Error(err)
			continue
		}

		if needsReissuing {
			logger.Infof("obtaining certificate for %s", mainDomain)
			err := certificate.ObtainCertificate(acmeClient, vaultClient, allDomains,
				cfg.DNSAddress, cfg.Acme.DNSChallengeProvider, cfg.Acme.DNSPropagationRequirement)
			if err != nil {
				failedDomains = append(failedDomains, mainDomain)
				certmetrics.CertificatesRenewalFailures.WithLabelValues(mainDomain).Inc()
				certmetrics.CertificatesChecked.WithLabelValues(mainDomain, "failure").Inc()
				logger.Error(err)
				continue
			}
			certmetrics.CertificatesRenewed.WithLabelValues(mainDomain).Inc()
			certmetrics.CertificatesChecked.WithLabelValues(mainDomain, "renewed").Inc()
			logger.Infof("certificate for %s renewed successfully", mainDomain)
		} else {
			certmetrics.CertificatesChecked.WithLabelValues(mainDomain, "valid").Inc()
			logger.Infof("certificate for %s is up to date, skipping renewal", mainDomain)
		}
	}

	if len(failedDomains) > 0 {
		logger.Fatalf("Failed to renew certificates for: %v", failedDomains)
	}
}
