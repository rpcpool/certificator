package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/vinted/certificator/pkg/config"
)

// testLogger discards output: the watcher goroutine outlives its test,
// and t.Log from a goroutine after the test ends panics.
func testLogger() *logrus.Logger {
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	return logger
}

func TestReadDataPlaneURLsFile(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    []string
		wantErr bool
	}{
		{
			name:    "single line, comma separated, matches the env var format",
			content: "http://10.0.0.1:5555,http://10.0.0.2:5555",
			want:    []string{"http://10.0.0.1:5555", "http://10.0.0.2:5555"},
		},
		{
			name:    "one url per line",
			content: "http://10.0.0.1:5555\nhttp://10.0.0.2:5555\n",
			want:    []string{"http://10.0.0.1:5555", "http://10.0.0.2:5555"},
		},
		{
			name:    "blank lines and stray whitespace are ignored",
			content: " http://10.0.0.1:5555 \n\n\thttp://10.0.0.2:5555\n  \n",
			want:    []string{"http://10.0.0.1:5555", "http://10.0.0.2:5555"},
		},
		{
			name:    "empty file is a valid, empty list - not an error",
			content: "",
			want:    nil,
		},
		{
			name:    "whitespace-only file is also a valid, empty list",
			content: "\n\n  \n",
			want:    nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "urls")
			if err := os.WriteFile(path, []byte(tt.content), 0o600); err != nil {
				t.Fatalf("failed to write fixture: %v", err)
			}

			got, err := readDataPlaneURLsFile(path)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("readDataPlaneURLsFile(%q) = %v, %v; want an error", tt.content, got, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("readDataPlaneURLsFile(%q) returned unexpected error: %v", tt.content, err)
			}
			if strings.Join(got, ",") != strings.Join(tt.want, ",") {
				t.Fatalf("readDataPlaneURLsFile(%q) = %v, want %v", tt.content, got, tt.want)
			}
		})
	}
}

func TestReadDataPlaneURLsFileMissing(t *testing.T) {
	_, err := readDataPlaneURLsFile(filepath.Join(t.TempDir(), "does-not-exist"))
	if err == nil {
		t.Fatal("readDataPlaneURLsFile of a missing file returned no error")
	}
}

func TestHAProxyClientSetConcurrentAccess(t *testing.T) {
	set := newHAProxyClientSet(nil)

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			set.Set(nil)
		}()
		go func() {
			defer wg.Done()
			_ = set.Get()
		}()
	}
	wg.Wait()
}

// TestWatchDataPlaneURLsFileReload exercises a temp-file-then-rename write,
// the same pattern Nomad's template renderer uses.
func TestWatchDataPlaneURLsFileReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dataplane-urls")

	if err := os.WriteFile(path, []byte("http://10.0.0.1:5555"), 0o600); err != nil {
		t.Fatalf("failed to seed fixture: %v", err)
	}

	cfg := config.Config{}
	cfg.Certificatee.HAProxyDataPlaneAPIURLsFile = path

	logger := testLogger()

	clientSet := newHAProxyClientSet(nil)
	go watchDataPlaneURLsFile(cfg, logger, clientSet)

	// Give the watcher a moment to start and register the directory watch.
	time.Sleep(50 * time.Millisecond)

	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte("http://10.0.0.2:5555,http://10.0.0.3:5555"), 0o600); err != nil {
		t.Fatalf("failed to write replacement fixture: %v", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatalf("failed to rename replacement fixture into place: %v", err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if len(clientSet.Get()) == 2 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}

	t.Fatalf("watchDataPlaneURLsFile did not pick up the renamed file within the deadline; got %d client(s)", len(clientSet.Get()))
}

// newSeededWatch seeds a one-URL fixture and starts watching it.
func newSeededWatch(t *testing.T) (path string, clientSet *haproxyClientSet) {
	t.Helper()

	dir := t.TempDir()
	path = filepath.Join(dir, "dataplane-urls")

	if err := os.WriteFile(path, []byte("http://10.0.0.1:5555"), 0o600); err != nil {
		t.Fatalf("failed to seed fixture: %v", err)
	}

	cfg := config.Config{}
	cfg.Certificatee.HAProxyDataPlaneAPIURLsFile = path
	// main() populates this from the file before the first build; mirror that.
	cfg.Certificatee.HAProxyDataPlaneAPIURLs = []string{"http://10.0.0.1:5555"}

	logger := testLogger()

	initial, err := createHAProxyClients(cfg, logger)
	if err != nil {
		t.Fatalf("failed to build initial client set: %v", err)
	}
	clientSet = newHAProxyClientSet(initial)

	go watchDataPlaneURLsFile(cfg, logger, clientSet)
	time.Sleep(50 * time.Millisecond)

	return path, clientSet
}

// TestWatchDataPlaneURLsFileAdoptsEmptyList: a file that reads fine but is
// empty becomes a real empty client set, not a failure.
func TestWatchDataPlaneURLsFileAdoptsEmptyList(t *testing.T) {
	path, clientSet := newSeededWatch(t)

	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, nil, 0o600); err != nil {
		t.Fatalf("failed to write empty replacement fixture: %v", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatalf("failed to rename empty replacement fixture into place: %v", err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if len(clientSet.Get()) == 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}

	t.Fatalf("watchDataPlaneURLsFile did not adopt the empty list within the deadline; got %d client(s)", len(clientSet.Get()))
}

// TestWatchDataPlaneURLsFileKeepsPreviousOnReadFailure: a genuine read
// failure (here, the file replaced by a directory) keeps the old set.
func TestWatchDataPlaneURLsFileKeepsPreviousOnReadFailure(t *testing.T) {
	path, clientSet := newSeededWatch(t)

	if err := os.Remove(path); err != nil {
		t.Fatalf("failed to remove fixture: %v", err)
	}
	if err := os.Mkdir(path, 0o750); err != nil {
		t.Fatalf("failed to replace fixture with a directory: %v", err)
	}

	time.Sleep(dataPlaneURLsReloadDebounce + 500*time.Millisecond)

	got := clientSet.Get()
	if len(got) != 1 || got[0].Endpoint() != "http://10.0.0.1:5555" {
		t.Fatalf("client set changed after an unreadable-file reload; got %d client(s), want the original 1 kept", len(got))
	}
}
