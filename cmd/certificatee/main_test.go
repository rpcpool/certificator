package main

import (
	"crypto/x509"
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

	if got := testutil.ToFloat64(certmetrics.HAProxyEndpointUp.WithLabelValues(server.URL, "reachable")); got != 1 {
		t.Fatalf("reachable metric = %v, want 1", got)
	}
	if got := testutil.ToFloat64(certmetrics.HAProxyEndpointUp.WithLabelValues(server.URL, "v3_ready")); got != 0 {
		t.Fatalf("v3_ready metric = %v, want 0", got)
	}
	if got := testutil.ToFloat64(certmetrics.HAProxyEndpointUp.WithLabelValues(server.URL, "v3_unsupported")); got != 1 {
		t.Fatalf("v3_unsupported metric = %v, want 1", got)
	}
	if got := testutil.ToFloat64(certmetrics.HAProxyEndpointUp.WithLabelValues(server.URL, "working")); got != 0 {
		t.Fatalf("working metric = %v, want 0", got)
	}
	if lastSync := healthChecker.lastSync(); !lastSync.IsZero() {
		t.Fatalf("health last sync = %s, want zero", lastSync)
	}
}
