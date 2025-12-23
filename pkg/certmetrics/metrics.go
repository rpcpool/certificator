package certmetrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/client_golang/prometheus/push"
	"github.com/sirupsen/logrus"
)

func StartMetricsServer(logger *logrus.Logger, address string) {
	if address == "" {
		logger.Debug("metrics listen address is empty, skipping metrics server start")
		return
	}

	metricsServer := &http.Server{
		Addr:    address,
		Handler: promhttp.Handler(),
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
	push.New(pushAddress, "certificator").Gatherer(prometheus.DefaultGatherer).Push()
}
