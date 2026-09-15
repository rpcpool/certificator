package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/sirupsen/logrus"
	"github.com/vinted/certificator/pkg/config"
	"github.com/vinted/certificator/pkg/haproxy"
)

// dataPlaneURLsReloadDebounce coalesces the burst of fs events a single
// logical write can produce (Nomad's template renderer writes to a temp
// file and renames it into place, which is a create + a write on the same
// path) into one reload.
const dataPlaneURLsReloadDebounce = 250 * time.Millisecond

// haproxyClientSet holds the live set of HAProxy clients certificatee talks
// to. It exists so a background file watcher can swap the set in place
// while maybeUpdateCertificates keeps reading a consistent snapshot on its
// own ticker cadence, with no restart in between.
type haproxyClientSet struct {
	mu      sync.RWMutex
	clients []*haproxy.Client
}

func newHAProxyClientSet(clients []*haproxy.Client) *haproxyClientSet {
	return &haproxyClientSet{clients: clients}
}

func (s *haproxyClientSet) Get() []*haproxy.Client {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.clients
}

func (s *haproxyClientSet) Set(clients []*haproxy.Client) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clients = clients
}

// readDataPlaneURLsFile parses a HAPROXY_DATAPLANE_API_URLS_FILE. It accepts
// the same comma-separated form as the HAPROXY_DATAPLANE_API_URLS env var on
// a single line, one URL per line, or a mix of both - whatever the writer on
// the other end finds convenient to render.
func readDataPlaneURLsFile(path string) ([]string, error) {
	data, err := os.ReadFile(path)
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

	if len(urls) == 0 {
		return nil, fmt.Errorf("%s contains no HAProxy Data Plane API URLs", path)
	}

	return urls, nil
}

// watchDataPlaneURLsFile watches HAProxyDataPlaneAPIURLsFile for changes and
// swaps clientSet's contents in place on every reload that produces a valid,
// non-empty client list. It runs until the watcher itself fails to start; a
// reload that fails (unreadable file, unparseable content, a bad URL) is
// logged and the previous client set is kept rather than emptied out or
// crashed - a transient render (a temp file mid-write, a blocking Consul
// query that hasn't populated a single endpoint yet) should never take
// certificatee's whole target list to zero.
func watchDataPlaneURLsFile(cfg config.Config, logger *logrus.Logger, clientSet *haproxyClientSet) {
	path := cfg.Certificatee.HAProxyDataPlaneAPIURLsFile
	dir := filepath.Dir(path)
	base := filepath.Base(path)

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		logger.Errorf("HAPROXY_DATAPLANE_API_URLS_FILE watcher: failed to create fsnotify watcher, live reload disabled: %v", err)
		return
	}
	defer watcher.Close()

	// Watch the containing directory, not the file itself: a rename-based
	// atomic render (write a temp file, rename over the target) replaces the
	// watched inode, which silently drops a watch held on the file path
	// alone.
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
