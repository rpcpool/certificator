package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/sirupsen/logrus"
	"github.com/vinted/certificator/pkg/config"
	"github.com/vinted/certificator/pkg/haproxy"
)

// Coalesces the create+write pair a single atomic render produces.
const dataPlaneURLsReloadDebounce = 250 * time.Millisecond

// haproxyClientSet lets a background file watcher swap the live client list
// while the ticker loop reads a consistent snapshot, no restart needed. A
// plain atomic swap of one value, not a map, so atomic.Pointer over a mutex.
type haproxyClientSet struct {
	clients atomic.Pointer[[]*haproxy.Client]
}

func newHAProxyClientSet(clients []*haproxy.Client) *haproxyClientSet {
	s := &haproxyClientSet{}
	s.Set(clients)
	return s
}

func (s *haproxyClientSet) Get() []*haproxy.Client {
	return *s.clients.Load()
}

func (s *haproxyClientSet) Set(clients []*haproxy.Client) {
	s.clients.Store(&clients)
}

// readDataPlaneURLsFile parses a comma- or newline-separated URL list.
// A file that reads but is empty returns (nil, nil), not an error.
func readDataPlaneURLsFile(path string) ([]string, error) {
	data, err := os.ReadFile(path) //nolint:gosec // G304: path is operator-supplied config (HAPROXY_DATAPLANE_API_URLS_FILE / a Nomad template destination), not user input
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", path, err)
	}

	var urls []string
	for _, line := range strings.Split(string(data), "\n") {
		for _, part := range strings.Split(line, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			urls = append(urls, part)
		}
	}

	return urls, nil
}

// watchDataPlaneURLsFile watches the URLs file and swaps clientSet on each
// valid change. A reload that fails to read keeps the previous client set.
func watchDataPlaneURLsFile(cfg config.Config, logger *logrus.Logger, clientSet *haproxyClientSet) {
	path := cfg.Certificatee.HAProxyDataPlaneAPIURLsFile
	dir := filepath.Dir(path)
	base := filepath.Base(path)

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		logger.Errorf("HAPROXY_DATAPLANE_API_URLS_FILE watcher: failed to create fsnotify watcher, live reload disabled: %v", err)
		return
	}
	defer func() {
		if err := watcher.Close(); err != nil {
			logger.Warnf("HAPROXY_DATAPLANE_API_URLS_FILE watcher: failed to close fsnotify watcher: %v", err)
		}
	}()

	// Watch the directory: a rename-based atomic write replaces the inode,
	// which drops a watch held on the file path alone.
	if err := watcher.Add(dir); err != nil {
		logger.Errorf("HAPROXY_DATAPLANE_API_URLS_FILE watcher: failed to watch %s, live reload disabled: %v", dir, err)
		return
	}

	logger.Infof("HAPROXY_DATAPLANE_API_URLS_FILE watcher: watching %s for changes", path)

	var debounce *time.Timer
	reload := make(chan struct{}, 1)
	fire := func() {
		select {
		case reload <- struct{}{}:
		default:
		}
	}

	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}
			if filepath.Base(event.Name) != base {
				continue
			}
			if event.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Rename) == 0 {
				continue
			}
			if debounce == nil {
				debounce = time.AfterFunc(dataPlaneURLsReloadDebounce, fire)
			} else {
				debounce.Reset(dataPlaneURLsReloadDebounce)
			}

		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			logger.Errorf("HAPROXY_DATAPLANE_API_URLS_FILE watcher error: %v", err)

		case <-reload:
			reloadDataPlaneURLs(path, cfg, logger, clientSet)
		}
	}
}

func reloadDataPlaneURLs(path string, cfg config.Config, logger *logrus.Logger, clientSet *haproxyClientSet) {
	urls, err := readDataPlaneURLsFile(path)
	if err != nil {
		logger.Warnf("HAPROXY_DATAPLANE_API_URLS_FILE reload: %v; keeping previous %d endpoint(s)", err, len(clientSet.Get()))
		return
	}

	reloadedCfg := cfg
	reloadedCfg.Certificatee.HAProxyDataPlaneAPIURLs = urls
	clients, err := createHAProxyClients(reloadedCfg, logger)
	if err != nil {
		logger.Warnf("HAPROXY_DATAPLANE_API_URLS_FILE reload: failed to build HAProxy clients: %v; keeping previous %d endpoint(s)", err, len(clientSet.Get()))
		return
	}

	clientSet.Set(clients)
	logger.Infof("HAPROXY_DATAPLANE_API_URLS_FILE reload: now configured with %d HAProxy endpoint(s)", len(clients))
	for _, client := range clients {
		logger.Infof("  - %s", client.Endpoint())
	}
}
