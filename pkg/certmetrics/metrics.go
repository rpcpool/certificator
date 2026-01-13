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
	// shared
	Up = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "up",
		Help: "Indicates if Certificatee is running (1 = up, 0 = down)",
	}, []string{"service", "version", "hostname", "environment"})
	CertificatesCurrent = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "certificator_certificates_current",
		Help: "Current number of valid certificates managed by Certificator",
	}, []string{"domain"})

	// certificator
	CertificatesReissued = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "certificator_certificates_reissued_total",
		Help: "Total number of certificates reissued by Certificator",
	}, []string{"domain"})
	CertificatesReissueFailures = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "certificator_certificates_reissue_failures_total",
		Help: "Total number of certificate reissue failures by Certificator",
	}, []string{"domain"})

	// certificatee
	CertificatesUpdatedOnDisk = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "certificatee_certificates_updated_on_disk_total",
		Help: "Total number of certificates updated on disk by Certificatee",
	}, []string{"domain"})
	CertificatesUpdateFailures = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "certificatee_certificates_update_failures_total",
		Help: "Total number of certificate update failures by Certificatee",
	}, []string{"domain"})

	// HAProxy-specific metrics
	HAProxyConnectionsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "certificatee_haproxy_connections_total",
		Help: "Total number of HAProxy connection attempts",
	}, []string{"endpoint", "status"})
	HAProxyConnectionRetries = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "certificatee_haproxy_connection_retries_total",
		Help: "Total number of HAProxy connection retries",
	}, []string{"endpoint"})
	HAProxyCertificatesUpdated = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "certificatee_haproxy_certificates_updated_total",
		Help: "Total number of certificates updated in HAProxy",
	}, []string{"endpoint", "domain"})
	HAProxyCertificatesChecked = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "certificatee_haproxy_certificates_checked_total",
		Help: "Total number of certificates checked in HAProxy",
	}, []string{"endpoint"})
	HAProxyEndpointsUp = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "certificatee_haproxy_endpoint_up",
		Help: "Indicates if HAProxy endpoint is reachable (1 = up, 0 = down)",
	}, []string{"endpoint"})
	HAProxyLastCheckTimestamp = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "certificatee_haproxy_last_check_timestamp_seconds",
		Help: "Unix timestamp of the last successful certificate check",
	}, []string{"endpoint"})
	HAProxyCommandDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "certificatee_haproxy_command_duration_seconds",
		Help:    "Duration of HAProxy Runtime API commands",
		Buckets: []float64{0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
	}, []string{"endpoint", "command"})
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
