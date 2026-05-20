package certmetrics

import (
	"bytes"
	"context"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/expfmt"
	"github.com/sirupsen/logrus"
)

type HealthChecker func(context.Context) error

var (
	// Shared metrics
	Up = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "up",
		Help: "Indicates if the service is running (1 = up, 0 = down)",
	}, []string{"service", "version", "hostname", "environment"})

	// Certificator metrics - certificate renewals
	CertificatesRenewed = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "certificator_certificates_renewed_total",
		Help: "Total number of certificates successfully renewed",
	}, []string{"domain"})
	CertificatesRenewalFailures = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "certificator_certificates_renewal_failures_total",
		Help: "Total number of certificate renewal failures",
	}, []string{"domain"})
	CertificatesChecked = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "certificator_certificates_checked_total",
		Help: "Total number of certificates checked",
	}, []string{"domain", "status"})

	// Certificatee metrics - certificate updates and expiry
	CertificatesUpdated = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "certificatee_certificates_updated_total",
		Help: "Total number of certificates successfully updated in HAProxy",
	}, []string{"endpoint", "domain"})
	CertificatesUpdateFailures = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "certificatee_certificates_update_failures_total",
		Help: "Total number of certificate update failures",
	}, []string{"endpoint", "domain"})
	CertificatesExpiring = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "certificatee_certificates_expiring",
		Help: "Number of certificates expiring within the renewal threshold",
	}, []string{"endpoint"})
	CertificatesTotal = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "certificatee_certificates_total",
		Help: "Total number of certificates managed per endpoint",
	}, []string{"endpoint"})
	CertificatesWildcard = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "certificatee_certificates_wildcard_total",
		Help: "Number of certificates with wildcard (*) in their storage filename, indicating pre-migration format",
	}, []string{"endpoint"})
	CertificateNotAfterTimestamp = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "certificatee_certificate_not_after_timestamp_seconds",
		Help: "Unix timestamp of the certificate not_after value reported by the HAProxy Data Plane API",
	}, []string{"endpoint", "domain"})
	CertificateMetadataLookupFailures = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "certificatee_certificate_metadata_lookup_failures_total",
		Help: "Total number of HAProxy Data Plane API per-certificate metadata lookup failures",
	}, []string{"endpoint", "domain"})

	// HAProxy endpoint health
	HAProxyEndpointUp = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "certificatee_haproxy_endpoint_up",
		Help: "Indicates HAProxy endpoint state for certificatee (1 = true, 0 = false)",
	}, []string{"endpoint", "state"})
	LastSyncTimestamp = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "certificatee_last_sync_timestamp_seconds",
		Help: "Unix timestamp of the last successful sync",
	}, []string{"endpoint"})
)

func StartMetricsServer(logger *logrus.Logger, address string, healthCheckers ...HealthChecker) {
	if address == "" {
		logger.Debug("metrics listen address is empty, skipping metrics server start")
		return
	}

	var healthChecker HealthChecker
	if len(healthCheckers) > 0 {
		healthChecker = healthCheckers[0]
	}

	metricsServer := &http.Server{
		Addr:              address,
		Handler:           newHandler(healthChecker),
		ReadHeaderTimeout: 100 * time.Millisecond,
	}

	go func() {
		logger.Infof("starting metrics server on %s", address)
		if err := metricsServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Errorf("metrics server error: %v", err)
		}
	}()
}

func newHandler(healthChecker HealthChecker) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		if healthChecker == nil {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok\n"))
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		if err := healthChecker(ctx); err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	return mux
}

func PushMetrics(logger *logrus.Logger, pushUrl string) {
	if pushUrl == "" {
		logger.Debug("metrics push url is empty, skipping metrics push")
		return
	}

	mts, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		logger.Errorf("could not gather metrics: %v", err)
		return
	}

	buf := &bytes.Buffer{}
	enc := expfmt.NewEncoder(buf, expfmt.FmtText)
	for _, mt := range mts {
		if err := enc.Encode(mt); err != nil {
			logger.Errorf("could not encode metric family %s: %v", mt.GetName(), err)
			return
		}
	}

	logger.Infof("pushing metrics to %s", pushUrl)
	resp, err := http.Post(pushUrl, "text/plain", buf) //nolint:gosec // URL is from trusted configuration
	if err != nil {
		logger.Errorf("could not push metrics: %v", err)
		return
	}
	defer func() { _ = resp.Body.Close() }()
}
