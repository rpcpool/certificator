package certmetrics

import (
	"bytes"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/expfmt"
	"github.com/sirupsen/logrus"
)

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

	// HAProxy endpoint health
	HAProxyEndpointUp = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "certificatee_haproxy_endpoint_up",
		Help: "Indicates if HAProxy endpoint is reachable (1 = up, 0 = down)",
	}, []string{"endpoint"})
	LastSyncTimestamp = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "certificatee_last_sync_timestamp_seconds",
		Help: "Unix timestamp of the last successful sync",
	}, []string{"endpoint"})
)

func StartMetricsServer(logger *logrus.Logger, address string) {
	if address == "" {
		logger.Debug("metrics listen address is empty, skipping metrics server start")
		return
	}

	metricsServer := &http.Server{
		Addr:              address,
		Handler:           promhttp.Handler(),
		ReadHeaderTimeout: 100 * time.Millisecond,
	}

	go func() {
		logger.Infof("starting metrics server on %s", address)
		if err := metricsServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Errorf("metrics server error: %v", err)
		}
	}()
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
