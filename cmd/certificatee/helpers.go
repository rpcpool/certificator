package main

import (
	"github.com/sirupsen/logrus"
	"github.com/vinted/certificator/pkg/config"
	"github.com/vinted/certificator/pkg/haproxy"
)

func createHAProxyClients(cfg config.Config, logger *logrus.Logger) ([]*haproxy.Client, error) {
	var clientConfigs []haproxy.ClientConfig
	for _, url := range cfg.Certificatee.HAProxyDataPlaneAPIURLs {
		clientConfigs = append(clientConfigs, haproxy.ClientConfig{
			BaseURL:            url,
			Username:           cfg.Certificatee.HAProxyDataPlaneAPIUser,
			Password:           cfg.Certificatee.HAProxyDataPlaneAPIPassword,
			InsecureSkipVerify: cfg.Certificatee.HAProxyDataPlaneAPIInsecure,
		})
	}

	return haproxy.NewClients(clientConfigs, logger)
}
