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

// testLogger discards output rather than routing it through t.Log: the
// watcher goroutine these tests start is never stopped and can still be
// running (and logging) after its test function returns, and t.Log from a
// goroutine that outlives its test panics.
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
			name:    "empty file is an error, not an empty list",
			content: "",
			wantErr: true,
		},
		{
			name:    "whitespace-only file is an error",
			content: "\n\n  \n",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "urls")
			if err := os.WriteFile(path, []byte(tt.content), 0o644); err != nil {
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

// TestWatchDataPlaneURLsFileReload exercises the exact write pattern a Nomad
// template render uses: write to a temp file in the same directory, then
// rename it over the target. A watch held on the file path alone misses this
// (the inode is replaced), which is why watchDataPlaneURLsFile watches the
// directory instead - this test would hang were that not the case.
func TestWatchDataPlaneURLsFileReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dataplane-urls")

	if err := os.WriteFile(path, []byte("http://10.0.0.1:5555"), 0o644); err != nil {
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
	if err := os.WriteFile(tmp, []byte("http://10.0.0.2:5555,http://10.0.0.3:5555"), 0o644); err != nil {
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

// TestWatchDataPlaneURLsFileKeepsPreviousOnBadReload confirms a reload that
// can't produce a valid client list (file briefly empty mid-write, unparsable
// content) leaves the previous, still-good client set in place instead of
// emptying it out - the whole point of this mechanism is to never repeat the
// "HAPROXY_DATAPLANE_API_URLS must be set" fatal exit on a transient render.
func TestWatchDataPlaneURLsFileKeepsPreviousOnBadReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dataplane-urls")

	if err := os.WriteFile(path, []byte("http://10.0.0.1:5555"), 0o644); err != nil {
		t.Fatalf("failed to seed fixture: %v", err)
	}

	cfg := config.Config{}
	cfg.Certificatee.HAProxyDataPlaneAPIURLsFile = path
	// createHAProxyClients reads HAProxyDataPlaneAPIURLs, not the file path
	// directly - main() populates this from the file at startup before the
	// first createHAProxyClients call, so mirror that here.
	cfg.Certificatee.HAProxyDataPlaneAPIURLs = []string{"http://10.0.0.1:5555"}

	logger := testLogger()

	initial, err := createHAProxyClients(cfg, logger)
	if err != nil {
		t.Fatalf("failed to build initial client set: %v", err)
	}
	clientSet := newHAProxyClientSet(initial)

	go watchDataPlaneURLsFile(cfg, logger, clientSet)
	time.Sleep(50 * time.Millisecond)

	if err := os.WriteFile(path, []byte(""), 0o644); err != nil {
		t.Fatalf("failed to write empty fixture: %v", err)
	}

	time.Sleep(dataPlaneURLsReloadDebounce + 500*time.Millisecond)

	got := clientSet.Get()
	if len(got) != 1 || got[0].Endpoint() != "http://10.0.0.1:5555" {
		t.Fatalf("client set changed after a bad reload; got %d client(s), want the original 1 kept", len(got))
	}
}
