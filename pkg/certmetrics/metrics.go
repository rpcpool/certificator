package certmetrics

import (
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/client_golang/prometheus/push"
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

func PushMetrics(logger *logrus.Logger, pushAddress string) {
	if pushAddress == "" {
		logger.Debug("metrics push address is empty, skipping metrics push")
		return
	}

	logger.Infof("pushing metrics to %s", pushAddress)
	if err := push.New(pushAddress, "certificator").Gatherer(prometheus.DefaultGatherer).Push(); err != nil {
		logger.Errorf("could not push metrics: %v", err)
	}
}
