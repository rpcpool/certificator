package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
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

func TestSyncCertificateSkipsNonExpiringUnusableVaultCandidate(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.PanicLevel)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("unexpected HAProxy request for skipped certificate: %s %s", r.Method, r.URL.String())
	}))
	defer server.Close()

	haproxyClient, err := haproxy.NewClient(haproxy.ClientConfig{BaseURL: server.URL}, logger)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	result, err := syncCertificate(
		"certs/_.mainnet.rpcpool.com.pem",
		[]string{"*.mainnet.rpcpool.com"},
		fakeCertificateStore{},
		haproxyClient,
		&haproxy.CertificateDetail{NotAfter: time.Now().AddDate(0, 0, 60)},
		30,
	)
	if err != nil {
		t.Fatalf("syncCertificate() error = %v, want nil", err)
	}
	if result.skipReason == "" {
		t.Fatal("skipReason is empty, want non-empty")
	}
	if result.storageSynced || result.runtimeUpdated {
		t.Fatalf("storageSynced=%v runtimeUpdated=%v, want both false", result.storageSynced, result.runtimeUpdated)
	}
}

func TestSyncCertificateErrorsWhenExpiringWithoutUsableVaultCandidate(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.PanicLevel)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("unexpected HAProxy request for failed certificate: %s %s", r.Method, r.URL.String())
	}))
	defer server.Close()

	haproxyClient, err := haproxy.NewClient(haproxy.ClientConfig{BaseURL: server.URL}, logger)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	result, err := syncCertificate(
		"certs/_.mainnet.rpcpool.com.pem",
		[]string{"*.mainnet.rpcpool.com"},
		fakeCertificateStore{},
		haproxyClient,
		&haproxy.CertificateDetail{NotAfter: time.Now().AddDate(0, 0, 10)},
		30,
	)
	if err == nil {
		t.Fatal("syncCertificate() error = nil, want error")
	}
	if !errors.Is(err, errNoUsableVaultCertificate) {
		t.Fatalf("syncCertificate() error = %v, want no usable Vault certificate", err)
	}
	if !result.isExpiring {
		t.Fatal("isExpiring = false, want true")
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
			_, _ = fmt.Fprintf(w, `{
				"storage_name":"certs/__nodes_rpcpool_com.pem",
				"not_after":%q,
				"not_before":"2026-05-08T00:00:00.000Z",
				"serial":"aa:bb",
				"subject_alternative_names":"DNS:nodes.rpcpool.com, DNS:*.nodes.rpcpool.com"
			}`, liveNotAfter)
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

func TestIsLegacyCertificateName(t *testing.T) {
	tests := []struct {
		name        string
		displayName string
		want        bool
	}{
		{"legacy wildcard", "__devnet_rpcpool_com.pem", true},
		{"legacy non-wildcard", "api_mainnet-beta_solana_com.pem", true},
		{"current wildcard", "_.devnet.rpcpool.com.pem", false},
		{"current non-wildcard", "api.mainnet-beta.solana.com.pem", false},
		{"current wildcard other extension", "_.devnet.rpcpool.com.crt", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isLegacyCertificateName(tt.displayName); got != tt.want {
				t.Errorf("isLegacyCertificateName(%q) = %v, want %v", tt.displayName, got, tt.want)
			}
		})
	}
}

// devnetCertDetailHandler builds a runtime ssl_certs detail response shared by
// a legacy/current duplicate pair: same live SAN, same serial, so the current
// duplicate is "stable" (no expiry, no serial mismatch) unless overridden.
func devnetCertDetailHandler(storageName, serial string, notAfter time.Time) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{
			"storage_name":%q,
			"not_after":%q,
			"not_before":"2026-05-08T00:00:00.000Z",
			"serial":%q,
			"subject_alternative_names":"DNS:*.devnet.rpcpool.com"
		}`, storageName, notAfter.UTC().Format(time.RFC3339Nano), serial)
	}
}

func TestCleanupLegacyDuplicateCertificatesRemovesConfirmedDuplicate(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.PanicLevel)

	certPEM, keyPEM, cert := testCertificateBundleForDomain(t, "*.devnet.rpcpool.com", 0x0B74A913, time.Now().AddDate(0, 0, 90))
	liveNotAfter := time.Now().AddDate(0, 0, 60)
	serial := cert.SerialNumber.Text(16)

	var deletes []string
	var storageWrites []string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v3/services/haproxy/runtime/ssl_certs":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`[
				{"description":"_.devnet.rpcpool.com.pem","storage_name":"certs/_.devnet.rpcpool.com.pem"},
				{"description":"__devnet_rpcpool_com.pem","storage_name":"certs/__devnet_rpcpool_com.pem"}
			]`))
		case r.Method == http.MethodGet && r.URL.Path == "/v3/services/haproxy/runtime/ssl_certs/certs/_.devnet.rpcpool.com.pem":
			devnetCertDetailHandler("certs/_.devnet.rpcpool.com.pem", serial, liveNotAfter)(w, r)
		case r.Method == http.MethodGet && r.URL.Path == "/v3/services/haproxy/runtime/ssl_certs/certs/__devnet_rpcpool_com.pem":
			devnetCertDetailHandler("certs/__devnet_rpcpool_com.pem", serial, liveNotAfter)(w, r)
		case r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/v3/services/haproxy/storage/ssl_certificates/"):
			storageWrites = append(storageWrites, r.URL.Path)
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/v3/services/haproxy/storage/ssl_certificates/"):
			if got := r.URL.Query().Get("skip_reload"); got != "true" {
				t.Errorf("skip_reload = %q, want true", got)
			}
			deletes = append(deletes, r.URL.Path)
			w.WriteHeader(http.StatusNoContent)
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
				"certificates/*.devnet.rpcpool.com": {"certificate": certPEM, "private_key": keyPEM},
			},
		},
		haproxyClient,
		healthChecker,
	)
	if err != nil {
		t.Fatalf("processHAProxyEndpoint() error = %v", err)
	}

	if len(deletes) != 1 || !strings.HasSuffix(deletes[0], "/__devnet_rpcpool_com.pem") {
		t.Fatalf("deletes = %v, want exactly one delete of the legacy duplicate", deletes)
	}
	// Regression check for the delete/recreate thrash loop: once a legacy
	// duplicate is classified, it must never go through the normal storage
	// sync again in the same cycle, or the next cycle's rediscovery (HAProxy
	// never drops it from ListCertificateRefs without a reload) would recreate
	// the very file we just deleted.
	if len(storageWrites) != 1 || !strings.HasSuffix(storageWrites[0], "/_.devnet.rpcpool.com.pem") {
		t.Fatalf("storageWrites = %v, want exactly one write, for the keeper only", storageWrites)
	}
}

// TestCleanupLegacyDuplicateCertificatesDoesNotThrashAcrossCycles is the
// direct regression test for the delete/recreate loop: HAProxy's runtime
// listing keeps reporting the legacy duplicate even after its storage file is
// deleted (confirmed against a real Data Plane API - deleting from storage
// with skip_reload=true never touches the live runtime listing). Running
// processHAProxyEndpoint twice against that unchanging listing must not
// recreate the deleted file on the second pass.
func TestCleanupLegacyDuplicateCertificatesDoesNotThrashAcrossCycles(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.PanicLevel)

	certPEM, keyPEM, cert := testCertificateBundleForDomain(t, "*.devnet.rpcpool.com", 0x0B74A913, time.Now().AddDate(0, 0, 90))
	liveNotAfter := time.Now().AddDate(0, 0, 60)
	serial := cert.SerialNumber.Text(16)

	var deletes []string
	var legacyStorageWrites []string
	var keeperStorageWrites []string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v3/services/haproxy/runtime/ssl_certs":
			// HAProxy keeps listing both names every cycle: this is the
			// stale, disconnected-from-disk runtime state that drove the
			// original bug.
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`[
				{"description":"_.devnet.rpcpool.com.pem","storage_name":"certs/_.devnet.rpcpool.com.pem"},
				{"description":"__devnet_rpcpool_com.pem","storage_name":"certs/__devnet_rpcpool_com.pem"}
			]`))
		case r.Method == http.MethodGet && r.URL.Path == "/v3/services/haproxy/runtime/ssl_certs/certs/_.devnet.rpcpool.com.pem":
			devnetCertDetailHandler("certs/_.devnet.rpcpool.com.pem", serial, liveNotAfter)(w, r)
		case r.Method == http.MethodGet && r.URL.Path == "/v3/services/haproxy/runtime/ssl_certs/certs/__devnet_rpcpool_com.pem":
			devnetCertDetailHandler("certs/__devnet_rpcpool_com.pem", serial, liveNotAfter)(w, r)
		case r.Method == http.MethodPut && r.URL.Path == "/v3/services/haproxy/storage/ssl_certificates/__devnet_rpcpool_com.pem":
			legacyStorageWrites = append(legacyStorageWrites, r.URL.Path)
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/v3/services/haproxy/storage/ssl_certificates/"):
			keeperStorageWrites = append(keeperStorageWrites, r.URL.Path)
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/v3/services/haproxy/storage/ssl_certificates/"):
			deletes = append(deletes, r.URL.Path)
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Fatalf("unexpected %s %q", r.Method, r.URL.String())
		}
	}))
	defer server.Close()

	haproxyClient, err := haproxy.NewClient(haproxy.ClientConfig{BaseURL: server.URL}, logger)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	cfg := config.Config{Certificatee: config.Certificatee{RenewBeforeDays: 30}}
	store := fakeCertificateStore{
		secretsByPath: map[string]map[string]any{
			"certificates/*.devnet.rpcpool.com": {"certificate": certPEM, "private_key": keyPEM},
		},
	}
	healthChecker := newCertificateeHealthChecker(nil, time.Minute)

	for cycle := 1; cycle <= 2; cycle++ {
		if err := processHAProxyEndpoint(logger, cfg, store, haproxyClient, healthChecker); err != nil {
			t.Fatalf("processHAProxyEndpoint() cycle %d error = %v", cycle, err)
		}
	}

	if len(legacyStorageWrites) != 0 {
		t.Fatalf("legacyStorageWrites = %v, want zero across both cycles - this is the thrash bug", legacyStorageWrites)
	}
	if len(keeperStorageWrites) != 2 {
		t.Fatalf("keeperStorageWrites = %v, want one per cycle", keeperStorageWrites)
	}
	if len(deletes) == 0 {
		t.Fatal("deletes is empty, want at least one delete attempt for the legacy duplicate")
	}
}

func TestCleanupLegacyDuplicateCertificatesSkipsWhenKeeperUnstable(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.PanicLevel)

	certPEM, keyPEM, cert := testCertificateBundleForDomain(t, "*.devnet.rpcpool.com", 0x0B74A913, time.Now().AddDate(0, 0, 90))
	liveNotAfter := time.Now().AddDate(0, 0, 60)
	vaultSerial := cert.SerialNumber.Text(16)

	var deletes []string
	var storageWrites []string
	var runtimeWrites []string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v3/services/haproxy/runtime/ssl_certs":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`[
				{"description":"_.devnet.rpcpool.com.pem","storage_name":"certs/_.devnet.rpcpool.com.pem"},
				{"description":"__devnet_rpcpool_com.pem","storage_name":"certs/__devnet_rpcpool_com.pem"}
			]`))
		case r.Method == http.MethodGet && r.URL.Path == "/v3/services/haproxy/runtime/ssl_certs/certs/_.devnet.rpcpool.com.pem":
			// Keeper's live serial does not match Vault's: this cycle needs a
			// runtime push, so it is not yet "stable".
			devnetCertDetailHandler("certs/_.devnet.rpcpool.com.pem", "DEADBEEF0000", liveNotAfter)(w, r)
		case r.Method == http.MethodGet && r.URL.Path == "/v3/services/haproxy/runtime/ssl_certs/certs/__devnet_rpcpool_com.pem":
			devnetCertDetailHandler("certs/__devnet_rpcpool_com.pem", vaultSerial, liveNotAfter)(w, r)
		case r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/v3/services/haproxy/storage/ssl_certificates/"):
			storageWrites = append(storageWrites, r.URL.Path)
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/v3/services/haproxy/runtime/ssl_certs/"):
			runtimeWrites = append(runtimeWrites, r.URL.Path)
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodDelete:
			deletes = append(deletes, r.URL.Path)
			w.WriteHeader(http.StatusNoContent)
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
				"certificates/*.devnet.rpcpool.com": {"certificate": certPEM, "private_key": keyPEM},
			},
		},
		haproxyClient,
		healthChecker,
	)
	if err != nil {
		t.Fatalf("processHAProxyEndpoint() error = %v", err)
	}

	if len(deletes) != 0 {
		t.Fatalf("deletes = %v, want no cleanup while the keeper still needs a runtime push", deletes)
	}
	// Falling back to the normal sync for the legacy duplicate this cycle
	// means both files get persisted to storage, and the keeper's runtime
	// gets the fresh push it needed - unmaintained certs are never left
	// behind just because we're deferring cleanup.
	if len(storageWrites) != 2 {
		t.Fatalf("storageWrites = %v, want both duplicates persisted while cleanup is deferred", storageWrites)
	}
	if len(runtimeWrites) != 1 || !strings.Contains(runtimeWrites[0], "_.devnet.rpcpool.com.pem") {
		t.Fatalf("runtimeWrites = %v, want exactly one runtime push, for the keeper", runtimeWrites)
	}
}

func TestClassifyLegacyDuplicatesSkipsAmbiguousGroups(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.PanicLevel)

	sanCert := &haproxy.CertificateDetail{SubjectAlternativeNames: "DNS:*.devnet.rpcpool.com"}

	t.Run("no current-format keeper", func(t *testing.T) {
		details := []certRefDetail{
			{ref: haproxy.CertificateRef{DisplayName: "__devnet_rpcpool_com.pem", APIName: "certs/__devnet_rpcpool_com.pem"}, haproxyCert: sanCert},
			{ref: haproxy.CertificateRef{DisplayName: "__devnet_rpcpool_com_v2.pem", APIName: "certs/__devnet_rpcpool_com_v2.pem"}, haproxyCert: sanCert},
		}
		got := classifyLegacyDuplicates(logger, "test-endpoint", details)
		if len(got) != 0 {
			t.Fatalf("classifyLegacyDuplicates() = %v, want empty: no current-format certificate to keep", got)
		}
	})

	t.Run("two current-format entries", func(t *testing.T) {
		details := []certRefDetail{
			{ref: haproxy.CertificateRef{DisplayName: "_.devnet.rpcpool.com.pem", APIName: "certs/_.devnet.rpcpool.com.pem"}, haproxyCert: sanCert},
			{ref: haproxy.CertificateRef{DisplayName: "devnet.rpcpool.com.pem", APIName: "certs/devnet.rpcpool.com.pem"}, haproxyCert: sanCert},
		}
		got := classifyLegacyDuplicates(logger, "test-endpoint", details)
		if len(got) != 0 {
			t.Fatalf("classifyLegacyDuplicates() = %v, want empty: ambiguous which entry to keep", got)
		}
	})

	t.Run("unambiguous pair still resolves", func(t *testing.T) {
		details := []certRefDetail{
			{ref: haproxy.CertificateRef{DisplayName: "_.devnet.rpcpool.com.pem", APIName: "certs/_.devnet.rpcpool.com.pem"}, haproxyCert: sanCert},
			{ref: haproxy.CertificateRef{DisplayName: "__devnet_rpcpool_com.pem", APIName: "certs/__devnet_rpcpool_com.pem"}, haproxyCert: sanCert},
		}
		got := classifyLegacyDuplicates(logger, "test-endpoint", details)
		want := map[string]string{"certs/__devnet_rpcpool_com.pem": "certs/_.devnet.rpcpool.com.pem"}
		if len(got) != len(want) || got["certs/__devnet_rpcpool_com.pem"] != want["certs/__devnet_rpcpool_com.pem"] {
			t.Fatalf("classifyLegacyDuplicates() = %v, want %v", got, want)
		}
	})
}
