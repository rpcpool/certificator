package main

import (
	"slices"

	"github.com/sirupsen/logrus"
	"github.com/vinted/certificator/pkg/config"
	"github.com/vinted/certificator/pkg/haproxy"
)

func createHAProxyClients(cfg config.Config, logger *logrus.Logger) ([]*haproxy.Client, error) {
	urls := dedupeURLs(cfg.Certificatee.HAProxyDataPlaneAPIURLs)
	if duplicates := len(cfg.Certificatee.HAProxyDataPlaneAPIURLs) - len(urls); duplicates > 0 {
		logger.Infof("Dropped %d duplicate HAProxy Data Plane API URL(s) from configuration", duplicates)
	}

	var clientConfigs []haproxy.ClientConfig
	for _, url := range urls {
		clientConfigs = append(clientConfigs, haproxy.ClientConfig{
			BaseURL:            url,
			Username:           cfg.Certificatee.HAProxyDataPlaneAPIUser,
			Password:           cfg.Certificatee.HAProxyDataPlaneAPIPassword,
			InsecureSkipVerify: cfg.Certificatee.HAProxyDataPlaneAPIInsecure,
		})
	}

	return haproxy.NewClients(clientConfigs, logger)
}

// dedupeURLs returns urls with exact duplicates removed. Consul-template can
// list the same Data Plane API endpoint more than once when a node matches
// multiple configured service tags (e.g. a node carrying both "canary" and a
// production tag), and processing the same endpoint twice per cycle is
// wasted work at best. Order is not preserved - callers only use this list
// to build HAProxy clients, which are processed independently either way.
func dedupeURLs(urls []string) []string {
	deduped := slices.Clone(urls)
	slices.Sort(deduped)
	return slices.Compact(deduped)
}
