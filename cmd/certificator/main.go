package main

import (
	"context"
	"strings"

	legoLog "github.com/go-acme/lego/v4/log"
	"github.com/sourcegraph/conc/pool"
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

	ctx := context.Background()
	workerPool := pool.New().WithErrors().WithContext(ctx).WithMaxGoroutines(cfg.MaxConcurrentRenewals)

	for _, dom := range cfg.Domains {
		workerPool.Go(func(ctx context.Context) error {
			allDomains := strings.Split(dom, ",")
			mainDomain := allDomains[0]
			cert, err := certificate.GetCertificate(mainDomain, vaultClient)
			if err != nil {
				return err
			}
			logger.Infof("checking certificate for %s", mainDomain)

			needsReissuing, err := certificate.NeedsReissuing(cert, allDomains, cfg.RenewBeforeDays, logger)
			if err != nil {
				return err
			}

			if !needsReissuing {
				certmetrics.CertificatesChecked.WithLabelValues(mainDomain, "valid").Inc()
				logger.Infof("certificate for %s is up to date, skipping renewal", mainDomain)
				return nil
			}

			logger.Infof("obtaining certificate for %s", mainDomain)
			if err := certificate.ObtainCertificate(acmeClient, vaultClient, allDomains,
				cfg.DNSAddress, cfg.Acme.DNSChallengeProvider, cfg.Acme.DNSPropagationRequirement); err != nil {
				certmetrics.CertificatesRenewalFailures.WithLabelValues(mainDomain).Inc()
				certmetrics.CertificatesChecked.WithLabelValues(mainDomain, "failure").Inc()
				return err
			}
			certmetrics.CertificatesRenewed.WithLabelValues(mainDomain).Inc()
			certmetrics.CertificatesChecked.WithLabelValues(mainDomain, "renewed").Inc()
			logger.Infof("certificate for %s renewed successfully", mainDomain)

			return nil
		})
	}

	if err := workerPool.Wait(); err != nil {
		logger.Fatal(err)
	}
}
