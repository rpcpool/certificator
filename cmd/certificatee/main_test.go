package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/sirupsen/logrus"
	"github.com/vinted/certificator/pkg/certmetrics"
	"github.com/vinted/certificator/pkg/config"
	"github.com/vinted/certificator/pkg/haproxy"
)

type fakeCertificateStore struct {
	secrets       map[string]any
	secretsByPath map[string]map[string]any
	err           error
	paths         *[]string
}

func (f fakeCertificateStore) KVRead(path string) (map[string]any, error) {
	if f.paths != nil {
		*f.paths = append(*f.paths, path)
	}
	if f.err != nil {
		return nil, f.err
	}
	if f.secretsByPath != nil {
		return f.secretsByPath[path], nil
	}

	return f.secrets, nil
}

func testCertificateBundle(t *testing.T, serial int64, notAfter time.Time) (string, string, *x509.Certificate) {
	t.Helper()
	return testCertificateBundleForDomain(t, "*.mainnet.rpcpool.com", serial, notAfter)
}

func testCertificateBundleForDomain(t *testing.T, domain string, serial int64, notAfter time.Time, additionalDomains ...string) (string, string, *x509.Certificate) {
	t.Helper()
	dnsNames := append([]string{domain}, additionalDomains...)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: domain},
		DNSNames:     dnsNames,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate() error = %v", err)
	}

	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate() error = %v", err)
	}

	return certPEM, keyPEM, cert
}

func TestShouldUpdateForLiveExpiry(t *testing.T) {
	t.Run("requires live metadata", func(t *testing.T) {
		_, _, _, err := shouldUpdateForLiveExpiry("example.com", nil, 30)
		if err == nil || !strings.Contains(err.Error(), "live certificate metadata") {
			t.Fatalf("expected live metadata error, got %v", err)
		}
	})

	t.Run("requires live not_after", func(t *testing.T) {
		_, _, _, err := shouldUpdateForLiveExpiry("example.com", &haproxy.CertificateDetail{}, 30)
		if err == nil || !strings.Contains(err.Error(), "missing not_after") {
			t.Fatalf("expected missing not_after error, got %v", err)
		}
	})

	t.Run("uses live expiry inside threshold", func(t *testing.T) {
		liveCert := &haproxy.CertificateDetail{
			NotAfter: time.Now().AddDate(0, 0, 10),
		}

		shouldUpdate, reason, isExpiring, err := shouldUpdateForLiveExpiry("example.com", liveCert, 30)
		if err != nil {
			t.Fatalf("shouldUpdateForLiveExpiry() error = %v", err)
		}
		if !shouldUpdate || !isExpiring {
			t.Fatalf("shouldUpdate=%v isExpiring=%v, want both true", shouldUpdate, isExpiring)
		}
		if !strings.Contains(reason, "live haproxy certificate expires") {
			t.Fatalf("reason = %q, want live haproxy expiry", reason)
		}
	})

	t.Run("does not update when live expiry is outside threshold", func(t *testing.T) {
		liveCert := &haproxy.CertificateDetail{
			NotAfter: time.Now().AddDate(0, 0, 60),
		}

		shouldUpdate, reason, isExpiring, err := shouldUpdateForLiveExpiry("example.com", liveCert, 30)
		if err != nil {
			t.Fatalf("shouldUpdateForLiveExpiry() error = %v", err)
		}
		if shouldUpdate || isExpiring || reason != "" {
			t.Fatalf("shouldUpdate=%v isExpiring=%v reason=%q, want no update", shouldUpdate, isExpiring, reason)
		}
	})
}

func TestValidateVaultCertificateForUpdate(t *testing.T) {
	now := time.Date(2026, time.July, 3, 12, 0, 0, 0, time.UTC)

	t.Run("rejects missing vault certificate", func(t *testing.T) {
		err := validateVaultCertificateForUpdateAt("example.com", nil, &haproxy.CertificateDetail{}, now)
		if err == nil || !strings.Contains(err.Error(), "does not exist in vault") {
			t.Fatalf("expected missing vault certificate error, got %v", err)
		}
	})

	t.Run("rejects expired vault certificate", func(t *testing.T) {
		vaultCert := &x509.Certificate{
			DNSNames: []string{"example.com"},
			NotAfter: now.Add(-time.Minute),
		}

		err := validateVaultCertificateForUpdateAt("example.com", vaultCert, &haproxy.CertificateDetail{}, now)
		if err == nil || !strings.Contains(err.Error(), "Vault certificate expired") {
			t.Fatalf("expected expired vault certificate error, got %v", err)
		}
	})

	t.Run("rejects SAN mismatch", func(t *testing.T) {
		vaultCert := &x509.Certificate{
			DNSNames: []string{"example.com"},
			NotAfter: now.AddDate(0, 0, 90),
		}
		liveCert := &haproxy.CertificateDetail{
			NotAfter:                now.AddDate(0, 0, 60),
			SubjectAlternativeNames: "DNS:example.com, DNS:www.example.com",
		}

		err := validateVaultCertificateForUpdateAt("example.com", vaultCert, liveCert, now)
		if err == nil || !strings.Contains(err.Error(), "do not match live HAProxy DNS names") {
			t.Fatalf("expected SAN mismatch rejection, got %v", err)
		}
	})

	t.Run("rejects certificate expiry downgrade", func(t *testing.T) {
		vaultCert := &x509.Certificate{
			DNSNames: []string{"example.com"},
			NotAfter: now.AddDate(0, 0, 30),
		}
		liveCert := &haproxy.CertificateDetail{
			NotAfter:                now.AddDate(0, 0, 60),
			SubjectAlternativeNames: "DNS:example.com",
		}

		err := validateVaultCertificateForUpdateAt("example.com", vaultCert, liveCert, now)
		if err == nil || !strings.Contains(err.Error(), "before live HAProxy certificate") {
			t.Fatalf("expected downgrade rejection, got %v", err)
		}
	})

	t.Run("accepts valid multi-SAN match in any order", func(t *testing.T) {
		vaultCert := &x509.Certificate{
			DNSNames: []string{"www.example.com", "example.com"},
			NotAfter: now.AddDate(0, 0, 90),
		}
		liveCert := &haproxy.CertificateDetail{
			NotAfter:                now.AddDate(0, 0, 60),
			SubjectAlternativeNames: "DNS:example.com, DNS:www.example.com",
		}

		if err := validateVaultCertificateForUpdateAt("example.com", vaultCert, liveCert, now); err != nil {
			t.Fatalf("validateVaultCertificateForUpdateAt() error = %v, want nil", err)
		}
	})
}

func TestDomainsForVaultUsesFilenameAndCertificateSANs(t *testing.T) {
	t.Run("uses SAN candidates first and filename fallback", func(t *testing.T) {
		domains := domainsForVault("api.mainnet-beta.solana.com.pem", &haproxy.CertificateDetail{
			SubjectAlternativeNames: "DNS:other.example.com, DNS:api.mainnet-beta.solana.com",
		})
		want := []string{"other.example.com", "api.mainnet-beta.solana.com"}
		if strings.Join(domains, "|") != strings.Join(want, "|") {
			t.Fatalf("domainsForVault() = %v, want %v", domains, want)
		}
	})

	t.Run("falls back to filename", func(t *testing.T) {
		domains := domainsForVault("_.nodes.rpcpool.com.pem", &haproxy.CertificateDetail{})
		want := []string{"*.nodes.rpcpool.com"}
		if strings.Join(domains, "|") != strings.Join(want, "|") {
			t.Fatalf("domainsForVault() = %v, want %v", domains, want)
		}
	})
}

func TestShouldUpdateForSerialMismatch(t *testing.T) {
	vaultCert := &x509.Certificate{SerialNumber: big.NewInt(0x1f5202e0)}

	t.Run("detects mismatch", func(t *testing.T) {
		shouldUpdate, reason := shouldUpdateForSerialMismatch(vaultCert, &haproxy.CertificateDetail{Serial: "aa:bb"})
		if !shouldUpdate {
			t.Fatal("expected update for serial mismatch")
		}
		if !strings.Contains(reason, "serial mismatch") {
			t.Fatalf("reason = %q, want serial mismatch", reason)
		}
	})

	t.Run("normalizes matching serials", func(t *testing.T) {
		shouldUpdate, reason := shouldUpdateForSerialMismatch(vaultCert, &haproxy.CertificateDetail{Serial: "1F:52:02:E0"})
		if shouldUpdate || reason != "" {
			t.Fatalf("shouldUpdate=%v reason=%q, want no update", shouldUpdate, reason)
		}
	})

	t.Run("ignores leading zero serial padding", func(t *testing.T) {
		shouldUpdate, reason := shouldUpdateForSerialMismatch(vaultCert, &haproxy.CertificateDetail{Serial: "01:F5:20:2E:0"})
		if shouldUpdate || reason != "" {
			t.Fatalf("shouldUpdate=%v reason=%q, want no update", shouldUpdate, reason)
		}
	})
}

func TestProcessHAProxyEndpointSkipsUnsupportedDataPlaneAPI(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.PanicLevel)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v3/services/haproxy/runtime/ssl_certs" {
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"message":"path /v3/services/haproxy/runtime/ssl_certs was not found"}`))
	}))
	defer server.Close()

	haproxyClient, err := haproxy.NewClient(haproxy.ClientConfig{BaseURL: server.URL}, logger)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	healthChecker := newCertificateeHealthChecker(nil, time.Minute)
	err = processHAProxyEndpoint(logger, config.Config{}, nil, haproxyClient, healthChecker)
	if err != nil {
		t.Fatalf("processHAProxyEndpoint() error = %v, want nil", err)
	}

	if got := testutil.ToFloat64(certmetrics.DataPlaneAPIVersion.WithLabelValues(server.URL, "v2")); got != 1 {
		t.Fatalf("dataplaneapi v2 metric = %v, want 1", got)
	}
	if got := testutil.ToFloat64(certmetrics.DataPlaneAPIVersion.WithLabelValues(server.URL, "v3")); got != 0 {
		t.Fatalf("dataplaneapi v3 metric = %v, want 0", got)
	}
	if lastSync := healthChecker.lastSync(); !lastSync.IsZero() {
		t.Fatalf("health last sync = %s, want zero", lastSync)
	}
}

func TestProcessHAProxyEndpointMarksV3ReadyEndpoint(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.PanicLevel)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v3/services/haproxy/runtime/ssl_certs" {
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[]`))
	}))
	defer server.Close()

	haproxyClient, err := haproxy.NewClient(haproxy.ClientConfig{BaseURL: server.URL}, logger)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	healthChecker := newCertificateeHealthChecker(nil, time.Minute)
	err = processHAProxyEndpoint(logger, config.Config{}, nil, haproxyClient, healthChecker)
	if err != nil {
		t.Fatalf("processHAProxyEndpoint() error = %v, want nil", err)
	}

	if got := testutil.ToFloat64(certmetrics.DataPlaneAPIVersion.WithLabelValues(server.URL, "v2")); got != 0 {
		t.Fatalf("dataplaneapi v2 metric = %v, want 0", got)
	}
	if got := testutil.ToFloat64(certmetrics.DataPlaneAPIVersion.WithLabelValues(server.URL, "v3")); got != 1 {
		t.Fatalf("dataplaneapi v3 metric = %v, want 1", got)
	}
	if lastSync := healthChecker.lastSync(); lastSync.IsZero() {
		t.Fatal("health last sync is zero, want successful sync timestamp")
	}
}

func TestSyncCertificatePersistsStorageWhenRuntimeCurrent(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.PanicLevel)

	certPEM, keyPEM, cert := testCertificateBundle(t, 0x1f5202e0, time.Now().AddDate(0, 0, 90))

	var storageWrites int
	var runtimeWrites int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v3/services/haproxy/storage/ssl_certificates/_.mainnet.rpcpool.com.pem":
			storageWrites++
			if r.Method != http.MethodPut {
				t.Fatalf("storage method = %s, want PUT", r.Method)
			}
			if got := r.URL.Query().Get("skip_reload"); got != "true" {
				t.Fatalf("skip_reload = %q, want true", got)
			}
			if got := r.Header.Get("Content-Type"); got != "text/plain" {
				t.Fatalf("storage content type = %q, want text/plain", got)
			}

			body := readRequestBody(t, r)
			if !strings.Contains(body, certPEM) || !strings.Contains(body, keyPEM) {
				t.Fatal("storage body did not contain certificate and private key")
			}
			w.WriteHeader(http.StatusOK)
		case strings.HasPrefix(r.URL.Path, "/v3/services/haproxy/runtime/ssl_certs/"):
			runtimeWrites++
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
	}))
	defer server.Close()

	haproxyClient, err := haproxy.NewClient(haproxy.ClientConfig{BaseURL: server.URL}, logger)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	result, err := syncCertificate(
		"certs/_.mainnet.rpcpool.com.pem",
		[]string{"*.mainnet.rpcpool.com"},
		fakeCertificateStore{secrets: map[string]any{"certificate": certPEM, "private_key": keyPEM}},
		haproxyClient,
		&haproxy.CertificateDetail{Serial: cert.SerialNumber.Text(16), NotAfter: cert.NotAfter},
		30,
	)
	if err != nil {
		t.Fatalf("syncCertificate() error = %v", err)
	}
	if !result.storageSynced {
		t.Fatal("storageSynced = false, want true")
	}
	if result.runtimeUpdated {
		t.Fatal("runtimeUpdated = true, want false")
	}
	if storageWrites != 1 {
		t.Fatalf("storageWrites = %d, want 1", storageWrites)
	}
	if runtimeWrites != 0 {
		t.Fatalf("runtimeWrites = %d, want 0", runtimeWrites)
	}
}

func TestSyncCertificateUpdatesRuntimeAfterStorageOnSerialMismatch(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.PanicLevel)

	certPEM, keyPEM, cert := testCertificateBundle(t, 0x1f5202e0, time.Now().AddDate(0, 0, 90))

	var storageWrites int
	var runtimeWrites int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v3/services/haproxy/storage/ssl_certificates/_.mainnet.rpcpool.com.pem":
			storageWrites++
			w.WriteHeader(http.StatusOK)
		case strings.HasPrefix(r.URL.Path, "/v3/services/haproxy/runtime/ssl_certs/"):
			runtimeWrites++
			if r.Method != http.MethodPut {
				t.Fatalf("runtime method = %s, want PUT", r.Method)
			}
			if got := r.Header.Get("Content-Type"); !strings.HasPrefix(got, "multipart/form-data;") {
				t.Fatalf("runtime content type = %q, want multipart/form-data", got)
			}
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
	}))
	defer server.Close()

	haproxyClient, err := haproxy.NewClient(haproxy.ClientConfig{BaseURL: server.URL}, logger)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	result, err := syncCertificate(
		"certs/_.mainnet.rpcpool.com.pem",
		[]string{"*.mainnet.rpcpool.com"},
		fakeCertificateStore{secrets: map[string]any{"certificate": certPEM, "private_key": keyPEM}},
		haproxyClient,
		&haproxy.CertificateDetail{Serial: "aa:bb", NotAfter: cert.NotAfter.Add(-time.Hour)},
		30,
	)
	if err != nil {
		t.Fatalf("syncCertificate() error = %v", err)
	}
	if !result.storageSynced || !result.runtimeUpdated {
		t.Fatalf("storageSynced=%v runtimeUpdated=%v, want both true", result.storageSynced, result.runtimeUpdated)
	}
	if storageWrites != 1 || runtimeWrites != 1 {
		t.Fatalf("storageWrites=%d runtimeWrites=%d, want 1 each", storageWrites, runtimeWrites)
	}
	if !strings.Contains(result.reason, "serial mismatch") {
		t.Fatalf("reason = %q, want serial mismatch", result.reason)
	}
}

func readRequestBody(t *testing.T, r *http.Request) string {
	t.Helper()

	body, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	return string(body)
}

func TestProcessHAProxyEndpointUsesSANAndExistingCertificateName(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.PanicLevel)

	singleSANCertPEM, singleSANKeyPEM, _ := testCertificateBundleForDomain(t, "nodes.rpcpool.com", 0x16d8b4e9, time.Now().AddDate(0, 0, 90))
	certPEM, keyPEM, cert := testCertificateBundleForDomain(t, "*.nodes.rpcpool.com", 0x26d8b4e9, time.Now().AddDate(0, 0, 90), "nodes.rpcpool.com")
	liveNotAfter := time.Now().AddDate(0, 0, 60).UTC().Format(time.RFC3339Nano)
	var vaultPaths []string
	var storageWrites []string
	var runtimeWrites []string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v3/services/haproxy/runtime/ssl_certs":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`[{"description":"__nodes_rpcpool_com.pem","storage_name":"certs/__nodes_rpcpool_com.pem"}]`))
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v3/services/haproxy/runtime/ssl_certs/"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(fmt.Sprintf(`{
				"storage_name":"certs/__nodes_rpcpool_com.pem",
				"not_after":%q,
				"not_before":"2026-05-08T00:00:00.000Z",
				"serial":"aa:bb",
				"subject_alternative_names":"DNS:nodes.rpcpool.com, DNS:*.nodes.rpcpool.com"
			}`, liveNotAfter)))
		case r.Method == http.MethodPut && r.URL.Path == "/v3/services/haproxy/storage/ssl_certificates/__nodes_rpcpool_com.pem":
			storageWrites = append(storageWrites, r.URL.Path)
			if got := r.URL.Query().Get("skip_reload"); got != "true" {
				t.Fatalf("skip_reload = %q, want true", got)
			}
			body := readRequestBody(t, r)
			if !strings.Contains(body, certPEM) || !strings.Contains(body, keyPEM) {
				t.Fatal("storage body did not contain certificate and private key")
			}
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/v3/services/haproxy/runtime/ssl_certs/"):
			runtimeWrites = append(runtimeWrites, r.URL.EscapedPath())
			if !strings.Contains(r.URL.EscapedPath(), "certs%2F__nodes_rpcpool_com.pem") {
				t.Fatalf("runtime path = %q, want existing sanitized certificate name", r.URL.EscapedPath())
			}
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected %s %q", r.Method, r.URL.String())
		}
	}))
	defer server.Close()

	haproxyClient, err := haproxy.NewClient(haproxy.ClientConfig{BaseURL: server.URL}, logger)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	healthChecker := newCertificateeHealthChecker(nil, time.Minute)
	err = processHAProxyEndpoint(
		logger,
		config.Config{Certificatee: config.Certificatee{RenewBeforeDays: 30}},
		fakeCertificateStore{
			secretsByPath: map[string]map[string]any{
				"certificates/nodes.rpcpool.com":   {"certificate": singleSANCertPEM, "private_key": singleSANKeyPEM},
				"certificates/*.nodes.rpcpool.com": {"certificate": certPEM, "private_key": keyPEM},
			},
			paths: &vaultPaths,
		},
		haproxyClient,
		healthChecker,
	)
	if err != nil {
		t.Fatalf("processHAProxyEndpoint() error = %v", err)
	}

	wantVaultPaths := []string{"certificates/nodes.rpcpool.com", "certificates/*.nodes.rpcpool.com"}
	if strings.Join(vaultPaths, "|") != strings.Join(wantVaultPaths, "|") {
		t.Fatalf("vaultPaths = %v, want %v", vaultPaths, wantVaultPaths)
	}
	if len(storageWrites) != 1 {
		t.Fatalf("storageWrites = %v, want one write", storageWrites)
	}
	if len(runtimeWrites) != 1 {
		t.Fatalf("runtimeWrites = %v, want one write", runtimeWrites)
	}
	if got := cert.SerialNumber.Text(16); got == "aabb" {
		t.Fatal("test certificate serial unexpectedly matches live serial")
	}
}
