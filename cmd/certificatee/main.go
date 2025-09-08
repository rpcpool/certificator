package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-acme/lego/certcrypto"
	legoLog "github.com/go-acme/lego/v4/log"
	"github.com/sirupsen/logrus"
	"github.com/vinted/certificator/pkg/certificate"
	"github.com/vinted/certificator/pkg/config"
	"github.com/vinted/certificator/pkg/vault"
)

func main() {
	logger := logrus.New()
	legoLog.Logger = logger

	cfg, err := config.LoadConfig()
	if err != nil {
		logger.Fatal(err)
	}

	switch cfg.Log.Format {
	case "JSON":
		logger.SetFormatter(&logrus.JSONFormatter{})
	case "LOGFMT":
		logger.SetFormatter(&logrus.TextFormatter{})
	}

	switch cfg.Log.Level {
	case "DEBUG":
		logger.SetLevel(logrus.DebugLevel)
	case "INFO":
		logger.SetLevel(logrus.InfoLevel)
	case "WARN":
		logger.SetLevel(logrus.WarnLevel)
	case "ERROR":
		logger.SetLevel(logrus.ErrorLevel)
	case "FATAL":
		logger.SetLevel(logrus.FatalLevel)
	}

	vaultClient, err := vault.NewVaultClient(cfg.Vault.ApproleRoleID,
		cfg.Vault.ApproleSecretID, cfg.Environment, cfg.Vault.KVStoragePath, logger)
	if err != nil {
		logger.Fatal(err)
	}

	certDirFiles, err := os.ReadDir(cfg.Certificatee.CertificatePath)
	if err != nil {
		logger.Fatalf("Error: %v, Path: '%s', have you set CERTIFICATEE_CERTIFICATE_PATH?", err, cfg.Certificatee.CertificatePath)
	}

	var certificateNames []string

	for _, certDirFile := range certDirFiles {
		extension := filepath.Ext(certDirFile.Name())
		if extension == cfg.Certificatee.CertificateExtension {
			certificateName := strings.TrimSuffix(certDirFile.Name(), extension)
			certificateNames = append(certificateNames, certificateName)
		}
	}

	logger.Infof("%v Certificates found!", len(certificateNames))

	for _, certificateName := range certificateNames {
		logger.Infof("Comparing certificates for %s", certificateName)
		certificateFullPath := filepath.Clean(filepath.Join(cfg.Certificatee.CertificatePath, certificateName+cfg.Certificatee.CertificateExtension))

		certificateFileContents, err := os.ReadFile(certificateFullPath)
		if err != nil {
			logger.Error(err)
			continue
		}

		parsedCertificateFile, err := certcrypto.ParsePEMBundle(certificateFileContents)
		if err != nil {
			logger.Error(err)
			continue
		}

		parsedVaultCert, err := certificate.GetCertificate(certificateName, vaultClient)
		if err != nil {
			logger.Error(err)
			continue
		}

		if !bytes.Equal(parsedCertificateFile[0].RawTBSCertificate, parsedVaultCert.RawTBSCertificate) {

			certificateSecrets, err := vaultClient.KVRead(certificate.VaultCertLocation(certificateName))
			if err != nil {
				logger.Error(err)
				continue
			}

			var newCertificateFile []byte

			if vaultCertificate, ok := certificateSecrets["certificate"].(string); ok {
				newCertificateFile = append(newCertificateFile, []byte(vaultCertificate)...)
			}
			if vaultPrivateKey, ok := certificateSecrets["private_key"].(string); ok {
				newCertificateFile = append(newCertificateFile, []byte(vaultPrivateKey)...)
			}

			// Write key to file
			err = os.WriteFile(certificateFullPath, newCertificateFile, 0600)
			if err != nil {
				logger.Error(err)
				continue
			} else {
				logger.Infof("Certificate %s updated!", certificateName)
			}
		} else {
			logger.Infof("Certificate %s matches!", certificateName)
		}
	}
}
