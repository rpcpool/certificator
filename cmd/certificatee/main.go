package main

import (
	"bytes"
	"fmt"
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

	certificateNames, err := getCertificateNames(cfg.Certificatee.CertificatePath, cfg.Certificatee.CertificateExtension)
	if err != nil {
		logger.Fatalf("Error: %v, Path: '%s', have you set CERTIFICATEE_CERTIFICATE_PATH?", err, cfg.Certificatee.CertificatePath)
	}

	logger.Infof("%v Certificates found!", len(certificateNames))

	for _, certificateName := range certificateNames {
		logger.Infof("Comparing certificates for %s", certificateName)
		certificateFullPath := filepath.Clean(filepath.Join(cfg.Certificatee.CertificatePath, certificateName+cfg.Certificatee.CertificateExtension))

		shouldUpdateCertificate, err := shouldUpdateCertificate(logger, certificateFullPath, certificateName, vaultClient)
		if err != nil {
			logger.Error(err)
			continue
		}

		if !shouldUpdateCertificate {
			logger.Infof("Certificate %s matches!", certificateName)
			continue
		}

		err = updateCertificate(certificateFullPath, certificateName, vaultClient)
		if err != nil {
			logger.Error(err)
			continue
		} else {
			logger.Infof("Certificate %s updated!", certificateName)
		}
	}
}

func getCertificateNames(path string, certificateExtension string) ([]string, error) {
	var certificateNames []string

	certDirFiles, err := os.ReadDir(path)
	if err != nil {
		return certificateNames, err
	}

	for _, certDirFile := range certDirFiles {
		fileExtension := filepath.Ext(certDirFile.Name())
		if certificateExtension == fileExtension {
			certificateName := strings.TrimSuffix(certDirFile.Name(), certificateExtension)
			certificateNames = append(certificateNames, certificateName)
		}
	}

	return certificateNames, nil
}

func shouldUpdateCertificate(logger *logrus.Logger, path string, certificateName string, vaultClient *vault.VaultClient) (bool, error) {
	certificateFileInfo, err := os.Stat(path)
	if err != nil {
		return false, fmt.Errorf("error reading file at path %s - %w", path, err)
	}

	if certificateFileInfo.Size() == 0 {
		logger.Infof("Certificate file for %s is empty, deploying certificate from vault..", certificateName)
		return true, nil
	}

	certificateFileContents, err := os.ReadFile(path)
	if err != nil {
		return false, fmt.Errorf("error reading file at path %s - %w", path, err)
	}

	parsedCertificateFile, err := certcrypto.ParsePEMBundle(certificateFileContents)
	if err != nil {
		return false, fmt.Errorf("error parsing PEM bundle - %w", err)

	}

	parsedVaultCert, err := certificate.GetCertificate(certificateName, vaultClient)
	if err != nil {
		return false, fmt.Errorf("error getting certificate %s from vault - %w", certificateName, err)
	}

	if parsedVaultCert == nil {
		logger.Infof("Certificate for %s does not exist in vault, ignoring..", certificateName)
		return false, nil
	}

	if bytes.Equal(parsedCertificateFile[0].RawTBSCertificate, parsedVaultCert.RawTBSCertificate) {
		return false, nil
	}

	return true, nil
}

func updateCertificate(path string, certificateName string, vaultClient *vault.VaultClient) error {
	certificateSecrets, err := vaultClient.KVRead(certificate.VaultCertLocation(certificateName))
	if err != nil {
		return fmt.Errorf("error reading data from vault key value storage %w", err)
	}

	var newCertificateFile []byte

	if vaultCertificate, ok := certificateSecrets["certificate"].(string); ok {
		newCertificateFile = append(newCertificateFile, []byte(vaultCertificate)...)
	}
	if vaultPrivateKey, ok := certificateSecrets["private_key"].(string); ok {
		newCertificateFile = append(newCertificateFile, []byte(vaultPrivateKey)...)
	}

	// Write key to file
	err = os.WriteFile(path, newCertificateFile, 0600)
	if err != nil {
		return fmt.Errorf("error writing new certificate to file %w", err)
	}

	return nil
}
