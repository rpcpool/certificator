//go:build integration

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/vinted/certificator/pkg/haproxy"
)

func TestCertificateeUpdatesCertViaDataPlane(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}

	haproxyPath := requireLookPath(t, "haproxy")
	dataplanePath := requireLookPath(t, "dataplaneapi")
	opensslPath := requireLookPath(t, "openssl")

	tempDir := t.TempDir()
	certsDir := filepath.Join(tempDir, "haproxy-certs")
	localCertsDir := filepath.Join(tempDir, "local-certs")
	mapsDir := filepath.Join(tempDir, "maps")
	spoeDir := filepath.Join(tempDir, "spoe")
	storageDir := filepath.Join(tempDir, "storage")
	runDir := mustMakeShortTempDir(t, "/tmp", "certificator-it-")
	mustMkdirAll(t, certsDir, localCertsDir, mapsDir, spoeDir, storageDir)

	domain := "example-test"
	haproxyCertPath := filepath.Join(certsDir, domain+".pem")
	localCertPath := filepath.Join(localCertsDir, domain+".pem")

	haproxyCertPEM, haproxySerial := mustSelfSignedPEM(t, domain, time.Now().Add(365*24*time.Hour), big.NewInt(1))
	localCertPEM, localSerial := mustSelfSignedPEM(t, domain, time.Now().Add(24*time.Hour), big.NewInt(2))
	if haproxySerial == localSerial {
		t.Fatalf("expected different serials for test certificates")
	}

	mustWriteFile(t, haproxyCertPath, haproxyCertPEM)
	mustWriteFile(t, localCertPath, localCertPEM)

	haproxyPort := freePort(t)
	socketPath := filepath.Join(runDir, "haproxy.sock")
	pidPath := filepath.Join(runDir, "haproxy.pid")
	haproxyCfgPath := filepath.Join(tempDir, "haproxy.cfg")
	haproxyCfg := fmt.Sprintf(`global
  log stdout format raw local0
  stats socket %s mode 600 level admin
  maxconn 256
userlist controller
  user admin insecure-password admin
defaults
  mode http
  timeout connect 5s
  timeout client 5s
  timeout server 5s
frontend fe_tls
  bind 127.0.0.1:%d ssl crt %s
  default_backend be
backend be
  server s1 127.0.0.1:8080
`, socketPath, haproxyPort, haproxyCertPath) + "\n"
	mustWriteFile(t, haproxyCfgPath, []byte(haproxyCfg))

	_, haproxyLogs := startProcess(t, haproxyPath, []string{"-f", haproxyCfgPath, "-db", "-p", pidPath}, nil, "")
	waitForSocket(t, socketPath, 5*time.Second, haproxyLogs)

	reloadScript := mustWriteReloadScript(t, tempDir, haproxyPath, haproxyCfgPath, pidPath)
	dataplaneCfgPath := filepath.Join(tempDir, "dataplaneapi.yaml")
	dataplaneArgs := []string{
		"-f", dataplaneCfgPath,
		"--scheme", "http",
		"--host", "127.0.0.1",
		"--config-file", haproxyCfgPath,
		"--haproxy-bin", haproxyPath,
		"--userlist", "controller",
		"--ssl-certs-dir", certsDir,
		"--general-storage-dir", storageDir,
		"--maps-dir", mapsDir,
		"--spoe-dir", spoeDir,
		"--reload-strategy", "custom",
		"--reload-cmd", reloadScript,
		"--restart-cmd", reloadScript,
		"--log-level", "info",
	}
	_, dataplaneLogs := startProcess(t, dataplanePath, dataplaneArgs, nil, "")
	apiURL := waitForDataPlaneURL(t, dataplaneLogs, 20*time.Second)
	waitForDataPlaneAPI(t, apiURL, "admin", "admin", domain+".pem", dataplaneLogs)

	pkgDir := mustGetwd(t)
	repoRoot := filepath.Clean(filepath.Join(pkgDir, "../.."))
	certificateeBin := filepath.Join(tempDir, "certificatee")
	buildCmd := exec.Command("go", "build", "-o", certificateeBin, "./cmd/certificatee")
	buildCmd.Dir = repoRoot
	buildCmd.Stdout = os.Stdout
	buildCmd.Stderr = os.Stderr
	if err := buildCmd.Run(); err != nil {
		t.Fatalf("failed to build certificatee: %v", err)
	}

	certificateeEnv := []string{
		fmt.Sprintf("HAPROXY_DATAPLANE_API_URLS=%s", apiURL),
		"HAPROXY_DATAPLANE_API_USER=admin",
		"HAPROXY_DATAPLANE_API_PASSWORD=admin",
		fmt.Sprintf("CERTIFICATEE_LOCAL_CERTS_DIR=%s", localCertsDir),
		"CERTIFICATEE_RENEW_BEFORE_DAYS=30",
		"CERTIFICATEE_UPDATE_INTERVAL=1h",
		"LOG_LEVEL=DEBUG",
	}

	_, certificateeLogs := startProcess(t, certificateeBin, nil, certificateeEnv, repoRoot)
	waitForSerialMatch(t, haproxyCertPath, localSerial, 10*time.Second, certificateeLogs, haproxyLogs, dataplaneLogs)
	waitForServerSerialMatch(t, opensslPath, fmt.Sprintf("127.0.0.1:%d", haproxyPort), domain, localSerial, 20*time.Second)
}

func TestHAProxyPrefersExactCertOverWildcard(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}

	haproxyPath := requireLookPath(t, "haproxy")
	opensslPath := requireLookPath(t, "openssl")

	tempDir := t.TempDir()
	certsDir := filepath.Join(tempDir, "haproxy-certs")
	runDir := mustMakeShortTempDir(t, "/tmp", "certificator-it-")
	mustMkdirAll(t, certsDir)

	domain := "example-test"
	wildcardDomain := "*." + domain

	exactCertPEM, exactSerial := mustSelfSignedPEM(t, domain, time.Now().Add(365*24*time.Hour), big.NewInt(11))
	wildcardCertPEM, wildcardSerial := mustSelfSignedPEM(t, wildcardDomain, time.Now().Add(365*24*time.Hour), big.NewInt(12))
	if exactSerial == wildcardSerial {
		t.Fatalf("expected different serials for test certificates")
	}

	exactCertPath := filepath.Join(certsDir, domain+".pem")
	wildcardCertPath := filepath.Join(certsDir, wildcardDomain+".pem")
	mustWriteFile(t, exactCertPath, exactCertPEM)
	mustWriteFile(t, wildcardCertPath, wildcardCertPEM)

	haproxyPort := freePort(t)
	socketPath := filepath.Join(runDir, "haproxy.sock")
	haproxyCfgPath := filepath.Join(tempDir, "haproxy.cfg")
	haproxyCfg := fmt.Sprintf(`global
  log stdout format raw local0
  stats socket %s mode 600 level admin
  maxconn 256
defaults
  mode http
  timeout connect 5s
  timeout client 5s
  timeout server 5s
frontend fe_tls
  bind 127.0.0.1:%d ssl crt %s alpn h2,http/1.1
  default_backend be
backend be
  server s1 127.0.0.1:8080
`, socketPath, haproxyPort, certsDir) + "\n"
	mustWriteFile(t, haproxyCfgPath, []byte(haproxyCfg))

	_, haproxyLogs := startProcess(t, haproxyPath, []string{"-f", haproxyCfgPath, "-db"}, nil, "")
	waitForSocket(t, socketPath, 5*time.Second, haproxyLogs)

	addr := fmt.Sprintf("127.0.0.1:%d", haproxyPort)
	subject, err := opensslServerSubject(t, opensslPath, addr, domain)
	if err != nil {
		t.Fatalf("failed to get server cert subject: %v", err)
	}

	if !strings.Contains(subject, "CN="+domain) && !strings.Contains(subject, "CN = "+domain) {
		t.Fatalf("expected exact certificate CN %q, got subject %q", domain, subject)
	}
}

func TestDataPlaneAcceptsUnderscoreWildcardName(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}

	haproxyPath := requireLookPath(t, "haproxy")
	dataplanePath := requireLookPath(t, "dataplaneapi")

	tempDir := t.TempDir()
	certsDir := filepath.Join(tempDir, "haproxy-certs")
	runDir := mustMakeShortTempDir(t, "/tmp", "certificator-it-")
	mustMkdirAll(t, certsDir)

	domain := "example-test"
	certName := "_." + domain + ".pem"
	certPEM, _ := mustSelfSignedPEM(t, "*."+domain, time.Now().Add(365*24*time.Hour), big.NewInt(21))
	initialCertPath := filepath.Join(certsDir, "bootstrap.pem")
	mustWriteFile(t, initialCertPath, certPEM)

	haproxyPort := freePort(t)
	socketPath := filepath.Join(runDir, "haproxy.sock")
	pidPath := filepath.Join(runDir, "haproxy.pid")
	haproxyCfgPath := filepath.Join(tempDir, "haproxy.cfg")
	haproxyCfg := fmt.Sprintf(`global
  log stdout format raw local0
  stats socket %s mode 600 level admin
  maxconn 256
userlist controller
  user admin insecure-password admin
defaults
  mode http
  timeout connect 5s
  timeout client 5s
  timeout server 5s
frontend fe_tls
  bind 127.0.0.1:%d ssl crt %s
  default_backend be
backend be
  server s1 127.0.0.1:8080
`, socketPath, haproxyPort, certsDir) + "\n"
	mustWriteFile(t, haproxyCfgPath, []byte(haproxyCfg))

	_, haproxyLogs := startProcess(t, haproxyPath, []string{"-f", haproxyCfgPath, "-db", "-p", pidPath}, nil, "")
	waitForSocket(t, socketPath, 5*time.Second, haproxyLogs)

	reloadScript := mustWriteReloadScript(t, tempDir, haproxyPath, haproxyCfgPath, pidPath)
	dataplaneCfgPath := filepath.Join(tempDir, "dataplaneapi.yaml")
	dataplaneArgs := []string{
		"-f", dataplaneCfgPath,
		"--scheme", "http",
		"--host", "127.0.0.1",
		"--config-file", haproxyCfgPath,
		"--haproxy-bin", haproxyPath,
		"--userlist", "controller",
		"--ssl-certs-dir", certsDir,
		"--general-storage-dir", filepath.Join(tempDir, "storage"),
		"--maps-dir", filepath.Join(tempDir, "maps"),
		"--spoe-dir", filepath.Join(tempDir, "spoe"),
		"--reload-strategy", "custom",
		"--reload-cmd", reloadScript,
		"--restart-cmd", reloadScript,
		"--log-level", "info",
	}
	_, dataplaneLogs := startProcess(t, dataplanePath, dataplaneArgs, nil, "")
	apiURL := waitForDataPlaneURL(t, dataplaneLogs, 20*time.Second)

	logger := logrus.New()
	client, err := haproxy.NewClient(haproxy.ClientConfig{
		BaseURL:  apiURL,
		Username: "admin",
		Password: "admin",
	}, logger)
	if err != nil {
		t.Fatalf("failed to create haproxy client: %v", err)
	}

	if err := client.CreateCertificate(certName, string(certPEM)); err != nil {
		t.Fatalf("failed to create certificate %s: %v", certName, err)
	}

	refs, err := client.ListCertificateRefs()
	if err != nil {
		t.Fatalf("failed to list certificates: %v", err)
	}

	found := false
	for _, ref := range refs {
		if ref.DisplayName == certName || filepath.Base(ref.FilePath) == certName {
			found = true
			break
		}
	}
	if !found {
		for _, ref := range refs {
			if strings.HasPrefix(ref.DisplayName, "_") || strings.HasPrefix(filepath.Base(ref.FilePath), "_") {
				found = true
				break
			}
		}
	}
	if !found {
		t.Fatalf("expected to find certificate with _ prefix in storage list")
	}
}

func TestWildcardReplacementSurvivesWildcardDeletion(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}

	haproxyPath := requireLookPath(t, "haproxy")
	dataplanePath := requireLookPath(t, "dataplaneapi")
	opensslPath := requireLookPath(t, "openssl")

	tempDir := t.TempDir()
	certsDir := filepath.Join(tempDir, "haproxy-certs")
	localCertsDir := filepath.Join(tempDir, "local-certs")
	runDir := mustMakeShortTempDir(t, "/tmp", "certificator-it-")
	mustMkdirAll(t, certsDir, localCertsDir)

	domain := "example-test"
	wildcardDomain := "*." + domain
	wildcardName := wildcardDomain + ".pem"

	oldPEM, oldSerial := mustSelfSignedPEM(t, wildcardDomain, time.Now().Add(24*time.Hour), big.NewInt(31))
	newPEM1, serial1 := mustSelfSignedPEM(t, wildcardDomain, time.Now().Add(24*time.Hour), big.NewInt(32))
	newPEM2, serial2 := mustSelfSignedPEM(t, wildcardDomain, time.Now().Add(24*time.Hour), big.NewInt(33))
	if serial1 == serial2 {
		t.Fatalf("expected different serials for updated certificates")
	}

	oldPath := filepath.Join(certsDir, wildcardName)
	mustWriteFile(t, oldPath, oldPEM)
	mustWriteFile(t, filepath.Join(localCertsDir, wildcardName), newPEM1)

	haproxyPort := freePort(t)
	socketPath := filepath.Join(runDir, "haproxy.sock")
	pidPath := filepath.Join(runDir, "haproxy.pid")
	haproxyCfgPath := filepath.Join(tempDir, "haproxy.cfg")
	haproxyCfg := fmt.Sprintf(`global
  log stdout format raw local0
  stats socket %s mode 600 level admin
  maxconn 256
userlist controller
  user admin insecure-password admin
defaults
  mode http
  timeout connect 5s
  timeout client 5s
  timeout server 5s
frontend fe_tls
  bind 127.0.0.1:%d ssl crt %s
  default_backend be
backend be
  server s1 127.0.0.1:8080
`, socketPath, haproxyPort, certsDir) + "\n"
	mustWriteFile(t, haproxyCfgPath, []byte(haproxyCfg))

	_, haproxyLogs := startProcess(t, haproxyPath, []string{"-f", haproxyCfgPath, "-db", "-p", pidPath}, nil, "")
	waitForSocket(t, socketPath, 5*time.Second, haproxyLogs)

	reloadScript := mustWriteReloadScript(t, tempDir, haproxyPath, haproxyCfgPath, pidPath)
	dataplaneCfgPath := filepath.Join(tempDir, "dataplaneapi.yaml")
	dataplaneArgs := []string{
		"-f", dataplaneCfgPath,
		"--scheme", "http",
		"--host", "127.0.0.1",
		"--config-file", haproxyCfgPath,
		"--haproxy-bin", haproxyPath,
		"--userlist", "controller",
		"--ssl-certs-dir", certsDir,
		"--general-storage-dir", filepath.Join(tempDir, "storage"),
		"--maps-dir", filepath.Join(tempDir, "maps"),
		"--spoe-dir", filepath.Join(tempDir, "spoe"),
		"--reload-strategy", "custom",
		"--reload-cmd", reloadScript,
		"--restart-cmd", reloadScript,
		"--log-level", "info",
	}
	_, dataplaneLogs := startProcess(t, dataplanePath, dataplaneArgs, nil, "")
	apiURL := waitForDataPlaneURL(t, dataplaneLogs, 20*time.Second)

	logger := logrus.New()
	client, err := haproxy.NewClient(haproxy.ClientConfig{
		BaseURL:  apiURL,
		Username: "admin",
		Password: "admin",
	}, logger)
	if err != nil {
		t.Fatalf("failed to create haproxy client: %v", err)
	}

	certSource := LocalCertSource{dir: localCertsDir}
	ref := haproxy.CertificateRef{
		DisplayName: wildcardName,
		FilePath:    oldPath,
	}

	if err := updateCertificate(ref, wildcardDomain, certSource, client); err != nil {
		t.Fatalf("failed to update wildcard certificate: %v", err)
	}

	underscorePath := findUnderscoreCertPath(t, client)
	serial, err := certSerialFromPEM(underscorePath)
	if err != nil {
		t.Fatalf("failed to read underscore cert serial: %v", err)
	}
	if serial != serial1 {
		t.Fatalf("expected underscore cert serial %s, got %s", serial1, serial)
	}
	waitForServerSerialMatch(t, opensslPath, fmt.Sprintf("127.0.0.1:%d", haproxyPort), "foo."+domain, oldSerial, 20*time.Second)

	if err := os.Remove(oldPath); err != nil {
		t.Fatalf("failed to remove old wildcard cert: %v", err)
	}

	mustWriteFile(t, filepath.Join(localCertsDir, wildcardName), newPEM2)
	if err := updateCertificate(ref, wildcardDomain, certSource, client); err != nil {
		t.Fatalf("failed to update underscore certificate: %v", err)
	}

	serial, err = certSerialFromPEM(underscorePath)
	if err != nil {
		t.Fatalf("failed to read underscore cert serial: %v", err)
	}
	if serial != serial2 {
		t.Fatalf("expected underscore cert serial %s after update, got %s", serial2, serial)
	}
	waitForServerSerialMatch(t, opensslPath, fmt.Sprintf("127.0.0.1:%d", haproxyPort), "foo."+domain, serial2, 20*time.Second)
}

func requireLookPath(t *testing.T, bin string) string {
	t.Helper()
	path, err := exec.LookPath(bin)
	if err != nil {
		t.Fatalf("required binary %s not found in PATH: %v", bin, err)
	}
	return path
}

func mustMkdirAll(t *testing.T, dirs ...string) {
	t.Helper()
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("failed to create dir %s: %v", dir, err)
		}
	}
}

func mustWriteFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("failed to write %s: %v", path, err)
	}
}

func mustWriteExecutable(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o700); err != nil {
		t.Fatalf("failed to write %s: %v", path, err)
	}
}

func mustSelfSignedPEM(t *testing.T, domain string, notAfter time.Time, serial *big.Int) ([]byte, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: domain,
		},
		DNSNames:    []string{domain},
		NotBefore:   time.Now().Add(-time.Hour),
		NotAfter:    notAfter,
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	return append(certPEM, keyPEM...), template.SerialNumber.String()
}

func startProcess(t *testing.T, binary string, args []string, env []string, dir string) (*exec.Cmd, *bytes.Buffer) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, binary, args...)
	if dir != "" {
		cmd.Dir = dir
	}
	if env != nil {
		cmd.Env = append(os.Environ(), env...)
	}
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start %s: %v", binary, err)
	}
	t.Cleanup(func() {
		cancel()
		_ = cmd.Wait()
	})
	return cmd, &output
}

func waitForSocket(t *testing.T, socketPath string, timeout time.Duration, logs *bytes.Buffer) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(socketPath); err == nil {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("haproxy socket did not appear at %s; logs:\n%s", socketPath, logs.String())
}

func waitForDataPlaneAPI(t *testing.T, baseURL, user, pass, wantCert string, logs *bytes.Buffer) {
	t.Helper()
	httpClient := &http.Client{Timeout: 2 * time.Second}
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		req, err := http.NewRequest("GET", fmt.Sprintf("%s/v2/services/haproxy/storage/ssl_certificates", baseURL), nil)
		if err != nil {
			t.Fatalf("failed to create request: %v", err)
		}
		req.SetBasicAuth(user, pass)
		resp, err := httpClient.Do(req)
		if err == nil {
			if resp.StatusCode == http.StatusOK {
				var certs []haproxy.SSLCertificateEntry
				if decodeErr := json.NewDecoder(resp.Body).Decode(&certs); decodeErr == nil {
					for _, cert := range certs {
						if cert.StorageName == wantCert || cert.File == wantCert || filepath.Base(cert.File) == wantCert {
							_ = resp.Body.Close()
							return
						}
					}
				}
			}
			_ = resp.Body.Close()
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("dataplane API did not list certificate %s; logs:\n%s", wantCert, logs.String())
}

func waitForDataPlaneURL(t *testing.T, logs *bytes.Buffer, timeout time.Duration) string {
	t.Helper()
	re := regexp.MustCompile(`Serving data plane at (http://[^\\s"]+)`)
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		matches := re.FindStringSubmatch(logs.String())
		if len(matches) == 2 {
			return strings.TrimSpace(matches[1])
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("dataplane API URL not found in logs within %s; logs:\n%s", timeout, logs.String())
	return ""
}

func waitForSerialMatch(t *testing.T, certPath, expectedSerial string, timeout time.Duration, logs ...*bytes.Buffer) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		serial, err := certSerialFromPEM(certPath)
		if err == nil && serial == expectedSerial {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	var combined strings.Builder
	for i, logBuf := range logs {
		if logBuf == nil {
			continue
		}
		if i > 0 {
			combined.WriteString("\n")
		}
		combined.WriteString(logBuf.String())
	}
	t.Fatalf("certificate at %s did not update to serial %s; logs:\n%s", certPath, expectedSerial, combined.String())
}

func certSerialFromPEM(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return "", fmt.Errorf("no certificate PEM found in %s", path)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", err
	}
	return cert.SerialNumber.String(), nil
}

func freePort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to get free port: %v", err)
	}
	defer func() { _ = listener.Close() }()
	return listener.Addr().(*net.TCPAddr).Port
}

func opensslServerSubject(t *testing.T, opensslPath, addr, serverName string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, opensslPath, "s_client", "-connect", addr, "-servername", serverName, "-showcerts")
	cmd.Stdin = strings.NewReader("")
	output, err := cmd.CombinedOutput()
	if err != nil && ctx.Err() == context.DeadlineExceeded {
		return "", fmt.Errorf("openssl s_client timed out: %s", output)
	}

	certPEM, err := extractFirstCertPEM(string(output))
	if err != nil {
		return "", err
	}

	certCmd := exec.CommandContext(ctx, opensslPath, "x509", "-noout", "-subject")
	certCmd.Stdin = strings.NewReader(certPEM)
	subjectOut, err := certCmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("openssl x509 failed: %s", subjectOut)
	}

	return strings.TrimSpace(string(subjectOut)), nil
}

func extractFirstCertPEM(output string) (string, error) {
	begin := strings.Index(output, "-----BEGIN CERTIFICATE-----")
	end := strings.Index(output, "-----END CERTIFICATE-----")
	if begin == -1 || end == -1 || end < begin {
		return "", fmt.Errorf("certificate PEM not found in output")
	}
	end += len("-----END CERTIFICATE-----")
	return output[begin:end] + "\n", nil
}

func waitForServerSerialMatch(t *testing.T, opensslPath, addr, serverName, expectedSerial string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		serial, err := opensslServerSerial(opensslPath, addr, serverName)
		if err == nil && serial == expectedSerial {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("server at %s did not present serial %s within %s", addr, expectedSerial, timeout)
}

func opensslServerSerial(opensslPath, addr, serverName string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, opensslPath, "s_client", "-connect", addr, "-servername", serverName, "-showcerts")
	cmd.Stdin = strings.NewReader("")
	output, err := cmd.CombinedOutput()
	if err != nil && ctx.Err() == context.DeadlineExceeded {
		return "", fmt.Errorf("openssl s_client timed out: %s", output)
	}

	certPEM, err := extractFirstCertPEM(string(output))
	if err != nil {
		return "", err
	}

	serial, err := serialFromPEM(certPEM)
	if err != nil {
		return "", err
	}
	return serial, nil
}

func serialFromPEM(pemData string) (string, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil || block.Type != "CERTIFICATE" {
		return "", fmt.Errorf("no certificate PEM found")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", err
	}
	return cert.SerialNumber.String(), nil
}

func findUnderscoreCertPath(t *testing.T, client *haproxy.Client) string {
	t.Helper()
	refs, err := client.ListCertificateRefs()
	if err != nil {
		t.Fatalf("failed to list certificates: %v", err)
	}

	for _, ref := range refs {
		if strings.HasPrefix(ref.DisplayName, "_") {
			if ref.FilePath != "" {
				return ref.FilePath
			}
			return ref.DisplayName
		}
		if strings.HasPrefix(filepath.Base(ref.FilePath), "_") {
			return ref.FilePath
		}
	}

	t.Fatalf("could not find underscore certificate in storage list")
	return ""
}

func mustGetwd(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working directory: %v", err)
	}
	return dir
}

func mustMakeShortTempDir(t *testing.T, base, pattern string) string {
	t.Helper()
	dir, err := os.MkdirTemp(base, pattern)
	if err != nil {
		t.Fatalf("failed to create temp dir in %s: %v", base, err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func mustWriteReloadScript(t *testing.T, dir, haproxyPath, cfgPath, pidPath string) string {
	t.Helper()
	scriptPath := filepath.Join(dir, "haproxy-reload.sh")
	script := fmt.Sprintf(`#!/bin/sh
set -eu
if [ -f %q ]; then
  oldpid="$(cat %q || true)"
else
  oldpid=""
fi
if [ -n "$oldpid" ]; then
  exec %q -f %q -p %q -sf "$oldpid"
else
  exec %q -f %q -p %q
fi
`, pidPath, pidPath, haproxyPath, cfgPath, pidPath, haproxyPath, cfgPath, pidPath)
	mustWriteExecutable(t, scriptPath, []byte(script))
	return scriptPath
}
