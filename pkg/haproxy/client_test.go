package haproxy

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

// =============================================================================
// Unit Tests for Helper Functions
// =============================================================================

func TestExtractDomainFromPath(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"/etc/haproxy/certs/example.com.pem", "example.com"},
		{"/etc/haproxy/certs/example.com.crt", "example.com"},
		{"/etc/haproxy/certs/example.com.cert", "example.com"},
		{"/etc/haproxy/certs/example.com.cer", "example.com"},
		{"/etc/haproxy/certs/example.com", "example.com"},
		{"example.com.pem", "example.com"},
		{"/path/to/my-domain.org.pem", "my-domain.org"},
		{"/certs/wildcard.example.com.pem", "wildcard.example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := ExtractDomainFromPath(tt.input)
			if got != tt.want {
				t.Errorf("ExtractDomainFromPath(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestIsExpiring(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name            string
		certInfo        *CertInfo
		renewBeforeDays int
		want            bool
	}{
		{
			name:            "nil certInfo",
			certInfo:        nil,
			renewBeforeDays: 30,
			want:            true,
		},
		{
			name: "expiring in 10 days, threshold 30",
			certInfo: &CertInfo{
				NotAfter: now.AddDate(0, 0, 10),
			},
			renewBeforeDays: 30,
			want:            true,
		},
		{
			name: "expiring in 60 days, threshold 30",
			certInfo: &CertInfo{
				NotAfter: now.AddDate(0, 0, 60),
			},
			renewBeforeDays: 30,
			want:            false,
		},
		{
			name: "already expired",
			certInfo: &CertInfo{
				NotAfter: now.AddDate(0, 0, -5),
			},
			renewBeforeDays: 30,
			want:            true,
		},
		{
			name: "expiring exactly at threshold",
			certInfo: &CertInfo{
				NotAfter: now.AddDate(0, 0, 30),
			},
			renewBeforeDays: 30,
			want:            true, // Before means strictly less than
		},
		{
			name: "expiring one day after threshold",
			certInfo: &CertInfo{
				NotAfter: now.AddDate(0, 0, 31),
			},
			renewBeforeDays: 30,
			want:            false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsExpiring(tt.certInfo, tt.renewBeforeDays)
			if got != tt.want {
				t.Errorf("IsExpiring() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNormalizeSerial(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"1F5202E0", "1F5202E0"},
		{"1f5202e0", "1F5202E0"},
		{"1F:52:02:E0", "1F5202E0"},
		{"1F 52 02 E0", "1F5202E0"},
		{"1f:52:02:e0", "1F5202E0"},
		{"  1F5202E0  ", "1F5202E0"},
		{"1F-52-02-E0", "1F5202E0"},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := NormalizeSerial(tt.input)
			if got != tt.want {
				t.Errorf("NormalizeSerial(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestParseDataPlaneAPITime(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
		check   func(t *testing.T, tm time.Time)
	}{
		{
			name:    "RFC3339 format",
			input:   "2024-08-12T17:05:34Z",
			wantErr: false,
			check: func(t *testing.T, tm time.Time) {
				if tm.Day() != 12 || tm.Month() != time.August || tm.Year() != 2024 {
					t.Errorf("got %v, want Aug 12 2024", tm)
				}
			},
		},
		{
			name:    "RFC3339 without T",
			input:   "2025-01-15T00:00:00Z",
			wantErr: false,
			check: func(t *testing.T, tm time.Time) {
				if tm.Month() != time.January || tm.Year() != 2025 {
					t.Errorf("got %v, want Jan 2025", tm)
				}
			},
		},
		{
			name:    "HAProxy format double digit day",
			input:   "Aug 12 17:05:34 2020 GMT",
			wantErr: false,
			check: func(t *testing.T, tm time.Time) {
				if tm.Day() != 12 || tm.Month() != time.August || tm.Year() != 2020 {
					t.Errorf("got %v, want Aug 12 2020", tm)
				}
			},
		},
		{
			name:    "HAProxy format single digit day padded",
			input:   "Aug 02 17:05:34 2020 GMT",
			wantErr: false,
			check: func(t *testing.T, tm time.Time) {
				if tm.Day() != 2 {
					t.Errorf("Day = %d, want 2", tm.Day())
				}
			},
		},
		{
			name:    "invalid format",
			input:   "not a date",
			wantErr: true,
		},
		{
			name:    "empty string",
			input:   "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tm, err := parseDataPlaneAPITime(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseDataPlaneAPITime(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if !tt.wantErr && tt.check != nil {
				tt.check(t, tm)
			}
		})
	}
}

// =============================================================================
// Unit Tests for Client Constructors
// =============================================================================

func TestNewClient(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.PanicLevel) // Suppress logs in tests

	tests := []struct {
		name    string
		config  ClientConfig
		wantErr bool
	}{
		{
			name: "empty baseURL",
			config: ClientConfig{
				BaseURL: "",
			},
			wantErr: true,
		},
		{
			name: "valid http URL",
			config: ClientConfig{
				BaseURL:  "http://localhost:5555",
				Username: "admin",
				Password: "secret",
			},
			wantErr: false,
		},
		{
			name: "valid https URL",
			config: ClientConfig{
				BaseURL:            "https://haproxy.example.com:5555",
				Username:           "admin",
				Password:           "secret",
				InsecureSkipVerify: true,
			},
			wantErr: false,
		},
		{
			name: "URL with trailing slash",
			config: ClientConfig{
				BaseURL: "http://localhost:5555/",
			},
			wantErr: false,
		},
		{
			name: "custom timeout",
			config: ClientConfig{
				BaseURL: "http://localhost:5555",
				Timeout: 60 * time.Second,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewClient(tt.config, logger)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewClient() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				expectedURL := strings.TrimSuffix(tt.config.BaseURL, "/")
				if client.baseURL != expectedURL {
					t.Errorf("client.baseURL = %q, want %q", client.baseURL, expectedURL)
				}
			}
		})
	}
}

func TestNewClients(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.PanicLevel)

	tests := []struct {
		name      string
		configs   []ClientConfig
		wantErr   bool
		wantCount int
	}{
		{
			name:    "empty slice",
			configs: []ClientConfig{},
			wantErr: true,
		},
		{
			name:    "nil slice",
			configs: nil,
			wantErr: true,
		},
		{
			name: "single endpoint",
			configs: []ClientConfig{
				{BaseURL: "http://localhost:5555", Username: "admin", Password: "secret"},
			},
			wantErr:   false,
			wantCount: 1,
		},
		{
			name: "multiple endpoints",
			configs: []ClientConfig{
				{BaseURL: "http://haproxy1:5555", Username: "admin", Password: "secret"},
				{BaseURL: "http://haproxy2:5555", Username: "admin", Password: "secret"},
				{BaseURL: "http://haproxy3:5555", Username: "admin", Password: "secret"},
			},
			wantErr:   false,
			wantCount: 3,
		},
		{
			name: "with empty baseURLs",
			configs: []ClientConfig{
				{BaseURL: "http://haproxy1:5555", Username: "admin", Password: "secret"},
				{BaseURL: ""},
				{BaseURL: "http://haproxy2:5555", Username: "admin", Password: "secret"},
			},
			wantErr:   false,
			wantCount: 2, // empty baseURLs are skipped
		},
		{
			name: "only empty baseURLs",
			configs: []ClientConfig{
				{BaseURL: ""},
				{BaseURL: ""},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clients, err := NewClients(tt.configs, logger)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewClients() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && len(clients) != tt.wantCount {
				t.Errorf("NewClients() returned %d clients, want %d", len(clients), tt.wantCount)
			}
		})
	}
}

func TestClientEndpoint(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.PanicLevel)

	client, err := NewClient(ClientConfig{
		BaseURL:  "http://localhost:5555",
		Username: "admin",
		Password: "secret",
	}, logger)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	if got := client.Endpoint(); got != "http://localhost:5555" {
		t.Errorf("Endpoint() = %q, want %q", got, "http://localhost:5555")
	}
}

// =============================================================================
// Mock HAProxy Data Plane API Server
// =============================================================================

// mockDataPlaneAPI simulates the HAProxy Data Plane API
type mockDataPlaneAPI struct {
	server       *httptest.Server
	handlers     map[string]http.HandlerFunc
	authRequired bool
	username     string
	password     string
	t            *testing.T
}

// newMockDataPlaneAPI creates a mock Data Plane API server
func newMockDataPlaneAPI(t *testing.T) *mockDataPlaneAPI {
	m := &mockDataPlaneAPI{
		handlers: make(map[string]http.HandlerFunc),
		t:        t,
	}

	m.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check basic auth if required
		if m.authRequired {
			user, pass, ok := r.BasicAuth()
			if !ok || user != m.username || pass != m.password {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
		}

		// Find matching handler by method + path
		key := r.Method + " " + r.URL.Path
		if handler, ok := m.handlers[key]; ok {
			handler(w, r)
			return
		}

		// Try prefix matching for dynamic paths (e.g., /v3/services/haproxy/runtime/certs/example.com.pem)
		for pattern, handler := range m.handlers {
			if strings.HasPrefix(key, pattern) {
				handler(w, r)
				return
			}
		}

		// Default 404
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"message": "not found"}`))
	}))

	return m
}

func (m *mockDataPlaneAPI) URL() string {
	return m.server.URL
}

func (m *mockDataPlaneAPI) Close() {
	m.server.Close()
}

func (m *mockDataPlaneAPI) SetAuth(username, password string) {
	m.authRequired = true
	m.username = username
	m.password = password
}

func (m *mockDataPlaneAPI) SetHandler(method, path string, handler http.HandlerFunc) {
	m.handlers[method+" "+path] = handler
}

// =============================================================================
// Integration Tests
// =============================================================================

func TestListCertificates(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.PanicLevel)

	tests := []struct {
		name       string
		response   []SSLCertificateEntry
		statusCode int
		want       []string
		wantErr    bool
	}{
		{
			name: "normal response with multiple certs",
			response: []SSLCertificateEntry{
				{File: "/etc/haproxy/certs/site1.pem", StorageName: "site1.pem"},
				{File: "/etc/haproxy/certs/site2.pem", StorageName: "site2.pem"},
			},
			statusCode: http.StatusOK,
			want:       []string{"site1.pem", "site2.pem"},
			wantErr:    false,
		},
		{
			name:       "empty response",
			response:   []SSLCertificateEntry{},
			statusCode: http.StatusOK,
			want:       nil,
			wantErr:    false,
		},
		{
			name: "certs with storage_name",
			response: []SSLCertificateEntry{
				{StorageName: "example.com.pem"},
				{StorageName: "test.com.pem"},
			},
			statusCode: http.StatusOK,
			want:       []string{"example.com.pem", "test.com.pem"},
			wantErr:    false,
		},
		{
			name: "single certificate",
			response: []SSLCertificateEntry{
				{File: "/etc/haproxy/certs/only.pem", StorageName: "only.pem"},
			},
			statusCode: http.StatusOK,
			want:       []string{"only.pem"},
			wantErr:    false,
		},
		{
			name:       "server error",
			response:   nil,
			statusCode: http.StatusInternalServerError,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := newMockDataPlaneAPI(t)
			defer mock.Close()

			mock.SetHandler("GET", "/v3/services/haproxy/storage/ssl_certificates", func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tt.statusCode)
				if tt.response != nil {
					_ = json.NewEncoder(w).Encode(tt.response)
				} else {
					_, _ = w.Write([]byte(`{"message": "error"}`))
				}
			})

			client, err := NewClient(ClientConfig{BaseURL: mock.URL()}, logger)
			if err != nil {
				t.Fatalf("NewClient() error = %v", err)
			}

			got, err := client.ListCertificates()
			if (err != nil) != tt.wantErr {
				t.Errorf("ListCertificates() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if len(got) != len(tt.want) {
				t.Errorf("ListCertificates() = %v, want %v", got, tt.want)
				return
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("ListCertificates()[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestGetCertificateInfo(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.PanicLevel)

	// Sample PEM certificate for testing (self-signed, CN=example.com)
	validPEM := `-----BEGIN CERTIFICATE-----
MIIDDTCCAfWgAwIBAgIUe9mCIn9FkwgXLlsXK6cwCMbavacwDQYJKoZIhvcNAQEL
BQAwFjEUMBIGA1UEAwwLZXhhbXBsZS5jb20wHhcNMjYwMTIwMTQwMTM0WhcNMjcw
MTIwMTQwMTM0WjAWMRQwEgYDVQQDDAtleGFtcGxlLmNvbTCCASIwDQYJKoZIhvcN
AQEBBQADggEPADCCAQoCggEBAK9vQbb4mhM0EKzKF40tM4UtZNquBfAR4RwaJWme
WowIe/zBK8qZxSO8W+1LmJguR1CLlytfQ3iv5y4LdQ1tsn350EmmHKfD31NOHxr9
F3GmsmSkHJBbukcpAl28ezTajtCImn6wciuui5ivUbKfuZXn4AEBNlaerGywQE2Y
0CNMKZ1/HnyrJymWyPb4tyJzfyYOdsPLwPt7GTAt4yqsRHnjIaIO2KD2OkmgFWMC
K5w64M8Zs7cg5Jk1zE0hFDKAE/3T78SYDGh+kHmDe68P75VACJBDgWYLWRAFWsOA
o8IrAUNYvCKHHXshEnR2HJSgoPT6nkNOgVzWTG52hnNuhLsCAwEAAaNTMFEwHQYD
VR0OBBYEFMljzE+9nN38vJhdB1ovTbiyuuZAMB8GA1UdIwQYMBaAFMljzE+9nN38
vJhdB1ovTbiyuuZAMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEB
ABI48y8xh9jQSYPmt9dIkMUmI8WyjkdVzBIs4vAqZ1DeOsxUJ3dLwmr1ImTTY7Sw
m6yDoTNInWsdjo5rjA9mgrkq5OTSVJNVe2bcNfZyFsTJ7B1OwGffCzBnFNwW/Zzf
OzZ53OaXmtWHeMP2cHhH7yEX7NVuB0HB/8CTu1F/jLuUTaaiCGbF+VCCHtLL5RAL
N4Vg0dt1Ls7qBpX/22o3cMNI15ixOOhW6Qug2at304/K0SJsXQifJ7SQiMRU84ov
FouJ5aRz+i5UvgFqDEMHY1PaEDXPAwHH+Kl3iC6L59McPRD3yRNlOMqquAOS2b8Y
kF7B68QUswmVK4Icz6zBgmo=
-----END CERTIFICATE-----`

	tests := []struct {
		name       string
		certPath   string
		pemData    string
		statusCode int
		wantErr    bool
		checkFunc  func(t *testing.T, info *CertInfo)
	}{
		{
			name:       "valid certificate info",
			certPath:   "example.com.pem",
			pemData:    validPEM,
			statusCode: http.StatusOK,
			wantErr:    false,
			checkFunc: func(t *testing.T, info *CertInfo) {
				if info.Subject == "" {
					t.Error("Subject should not be empty")
				}
				if info.NotAfter.IsZero() {
					t.Error("NotAfter should be set")
				}
			},
		},
		{
			name:       "certificate not found",
			certPath:   "notfound.pem",
			pemData:    "",
			statusCode: http.StatusNotFound,
			wantErr:    true,
		},
		{
			name:       "server error",
			certPath:   "error.pem",
			pemData:    "",
			statusCode: http.StatusInternalServerError,
			wantErr:    true,
		},
		{
			name:       "invalid PEM data",
			certPath:   "invalid.pem",
			pemData:    "not a valid PEM",
			statusCode: http.StatusOK,
			wantErr:    true, // Should fail to parse
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := newMockDataPlaneAPI(t)
			defer mock.Close()

			mock.SetHandler("GET", "/v3/services/haproxy/storage/ssl_certificates/"+tt.certPath, func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)
				if tt.statusCode == http.StatusOK {
					_, _ = w.Write([]byte(tt.pemData))
				} else {
					_, _ = w.Write([]byte(`{"message": "error"}`))
				}
			})

			client, err := NewClient(ClientConfig{BaseURL: mock.URL()}, logger)
			if err != nil {
				t.Fatalf("NewClient() error = %v", err)
			}

			info, err := client.GetCertificateInfo(tt.certPath)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetCertificateInfo() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && tt.checkFunc != nil {
				tt.checkFunc(t, info)
			}
		})
	}
}

func TestUpdateCertificate(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.PanicLevel)

	tests := []struct {
		name       string
		certName   string
		pemData    string
		statusCode int
		wantErr    bool
	}{
		{
			name:       "success - certificate updated",
			certName:   "example.com.pem",
			pemData:    "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
			statusCode: http.StatusOK,
			wantErr:    false,
		},
		{
			name:       "success - accepted",
			certName:   "example.com.pem",
			pemData:    "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
			statusCode: http.StatusAccepted,
			wantErr:    false,
		},
		{
			name:       "error - not found",
			certName:   "notfound.pem",
			pemData:    "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
			statusCode: http.StatusNotFound,
			wantErr:    true,
		},
		{
			name:       "error - bad request",
			certName:   "bad.pem",
			pemData:    "invalid pem",
			statusCode: http.StatusBadRequest,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := newMockDataPlaneAPI(t)
			defer mock.Close()

			mock.SetHandler("PUT", "/v3/services/haproxy/runtime/certs/"+tt.certName, func(w http.ResponseWriter, r *http.Request) {
				// Verify content type is multipart
				contentType := r.Header.Get("Content-Type")
				if !strings.Contains(contentType, "multipart/form-data") {
					t.Errorf("Expected multipart/form-data content type, got %s", contentType)
				}

				// Read the multipart form
				err := r.ParseMultipartForm(10 << 20) // 10 MB
				if err != nil {
					t.Errorf("Failed to parse multipart form: %v", err)
				}

				// Verify file was uploaded
				file, _, err := r.FormFile("file_upload")
				if err != nil {
					t.Errorf("Failed to get file from form: %v", err)
				} else {
					defer func() { _ = file.Close() }()
					data, _ := io.ReadAll(file)
					if string(data) != tt.pemData {
						t.Errorf("File data = %q, want %q", string(data), tt.pemData)
					}
				}

				w.WriteHeader(tt.statusCode)
			})

			client, err := NewClient(ClientConfig{BaseURL: mock.URL()}, logger)
			if err != nil {
				t.Fatalf("NewClient() error = %v", err)
			}

			err = client.UpdateCertificate(tt.certName, tt.pemData)
			if (err != nil) != tt.wantErr {
				t.Errorf("UpdateCertificate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestCreateCertificate(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.PanicLevel)

	tests := []struct {
		name       string
		certName   string
		pemData    string
		statusCode int
		wantErr    bool
	}{
		{
			name:       "success - certificate created",
			certName:   "new.example.com.pem",
			pemData:    "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
			statusCode: http.StatusCreated,
			wantErr:    false,
		},
		{
			name:       "success - OK status",
			certName:   "new.example.com.pem",
			pemData:    "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
			statusCode: http.StatusOK,
			wantErr:    false,
		},
		{
			name:       "error - conflict (already exists)",
			certName:   "existing.pem",
			pemData:    "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
			statusCode: http.StatusConflict,
			wantErr:    true,
		},
		{
			name:       "error - bad request",
			certName:   "bad.pem",
			pemData:    "invalid pem",
			statusCode: http.StatusBadRequest,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := newMockDataPlaneAPI(t)
			defer mock.Close()

			mock.SetHandler("POST", "/v3/services/haproxy/runtime/certs", func(w http.ResponseWriter, r *http.Request) {
				// Verify content type is multipart
				contentType := r.Header.Get("Content-Type")
				if !strings.Contains(contentType, "multipart/form-data") {
					t.Errorf("Expected multipart/form-data content type, got %s", contentType)
				}

				// Read the multipart form
				err := r.ParseMultipartForm(10 << 20) // 10 MB
				if err != nil {
					t.Errorf("Failed to parse multipart form: %v", err)
				}

				// Verify file was uploaded
				file, header, err := r.FormFile("file_upload")
				if err != nil {
					t.Errorf("Failed to get file from form: %v", err)
				} else {
					defer func() { _ = file.Close() }()
					if header.Filename != tt.certName {
						t.Errorf("Filename = %q, want %q", header.Filename, tt.certName)
					}
					data, _ := io.ReadAll(file)
					if string(data) != tt.pemData {
						t.Errorf("File data = %q, want %q", string(data), tt.pemData)
					}
				}

				w.WriteHeader(tt.statusCode)
			})

			client, err := NewClient(ClientConfig{BaseURL: mock.URL()}, logger)
			if err != nil {
				t.Fatalf("NewClient() error = %v", err)
			}

			err = client.CreateCertificate(tt.certName, tt.pemData)
			if (err != nil) != tt.wantErr {
				t.Errorf("CreateCertificate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestDeleteCertificate(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.PanicLevel)

	tests := []struct {
		name       string
		certName   string
		statusCode int
		wantErr    bool
	}{
		{
			name:       "success - no content",
			certName:   "example.com.pem",
			statusCode: http.StatusNoContent,
			wantErr:    false,
		},
		{
			name:       "success - OK",
			certName:   "example.com.pem",
			statusCode: http.StatusOK,
			wantErr:    false,
		},
		{
			name:       "error - not found",
			certName:   "notfound.pem",
			statusCode: http.StatusNotFound,
			wantErr:    true,
		},
		{
			name:       "error - server error",
			certName:   "error.pem",
			statusCode: http.StatusInternalServerError,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := newMockDataPlaneAPI(t)
			defer mock.Close()

			mock.SetHandler("DELETE", "/v3/services/haproxy/runtime/certs/"+tt.certName, func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)
			})

			client, err := NewClient(ClientConfig{BaseURL: mock.URL()}, logger)
			if err != nil {
				t.Fatalf("NewClient() error = %v", err)
			}

			err = client.DeleteCertificate(tt.certName)
			if (err != nil) != tt.wantErr {
				t.Errorf("DeleteCertificate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// =============================================================================
// Authentication Tests
// =============================================================================

func TestBasicAuth(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.PanicLevel)

	mock := newMockDataPlaneAPI(t)
	defer mock.Close()
	mock.SetAuth("admin", "secret")

	mock.SetHandler("GET", "/v3/services/haproxy/storage/ssl_certificates", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode([]SSLCertificateEntry{})
	})

	t.Run("valid credentials", func(t *testing.T) {
		client, err := NewClient(ClientConfig{
			BaseURL:  mock.URL(),
			Username: "admin",
			Password: "secret",
		}, logger)
		if err != nil {
			t.Fatalf("NewClient() error = %v", err)
		}

		_, err = client.ListCertificates()
		if err != nil {
			t.Errorf("ListCertificates() with valid auth error = %v", err)
		}
	})

	t.Run("invalid credentials", func(t *testing.T) {
		client, err := NewClient(ClientConfig{
			BaseURL:  mock.URL(),
			Username: "admin",
			Password: "wrong",
		}, logger)
		if err != nil {
			t.Fatalf("NewClient() error = %v", err)
		}

		_, err = client.ListCertificates()
		if err == nil {
			t.Error("ListCertificates() with invalid auth expected error, got nil")
		}
	})

	t.Run("no credentials", func(t *testing.T) {
		client, err := NewClient(ClientConfig{
			BaseURL: mock.URL(),
		}, logger)
		if err != nil {
			t.Fatalf("NewClient() error = %v", err)
		}

		_, err = client.ListCertificates()
		if err == nil {
			t.Error("ListCertificates() without auth expected error, got nil")
		}
	})
}

// =============================================================================
// Connection Error Tests
// =============================================================================

func TestConnectionError(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.PanicLevel)

	// Create client pointing to non-existent server
	client, err := NewClient(ClientConfig{
		BaseURL: "http://127.0.0.1:59999",
		Timeout: 100 * time.Millisecond,
	}, logger)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	// Disable retries for faster test
	client.SetRetryConfig(RetryConfig{
		MaxRetries: 0,
		BaseDelay:  10 * time.Millisecond,
		MaxDelay:   50 * time.Millisecond,
	})

	_, err = client.ListCertificates()
	if err == nil {
		t.Error("ListCertificates() expected connection error, got nil")
	}
}

// =============================================================================
// Retry Logic Tests
// =============================================================================

func TestDefaultRetryConfig(t *testing.T) {
	config := DefaultRetryConfig()

	if config.MaxRetries != DefaultMaxRetries {
		t.Errorf("MaxRetries = %d, want %d", config.MaxRetries, DefaultMaxRetries)
	}
	if config.BaseDelay != DefaultRetryBaseDelay {
		t.Errorf("BaseDelay = %v, want %v", config.BaseDelay, DefaultRetryBaseDelay)
	}
	if config.MaxDelay != DefaultRetryMaxDelay {
		t.Errorf("MaxDelay = %v, want %v", config.MaxDelay, DefaultRetryMaxDelay)
	}
}

func TestClientRetryConfig(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.PanicLevel)

	client, err := NewClient(ClientConfig{BaseURL: "http://localhost:5555"}, logger)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	// Check default config is applied
	config := client.GetRetryConfig()
	if config.MaxRetries != DefaultMaxRetries {
		t.Errorf("Default MaxRetries = %d, want %d", config.MaxRetries, DefaultMaxRetries)
	}

	// Set custom config
	customConfig := RetryConfig{
		MaxRetries: 5,
		BaseDelay:  500 * time.Millisecond,
		MaxDelay:   10 * time.Second,
	}
	client.SetRetryConfig(customConfig)

	// Verify custom config
	config = client.GetRetryConfig()
	if config.MaxRetries != 5 {
		t.Errorf("Custom MaxRetries = %d, want 5", config.MaxRetries)
	}
	if config.BaseDelay != 500*time.Millisecond {
		t.Errorf("Custom BaseDelay = %v, want 500ms", config.BaseDelay)
	}
}

func TestCalculateBackoff(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.PanicLevel)

	client, err := NewClient(ClientConfig{BaseURL: "http://localhost:5555"}, logger)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	// Set known config for predictable testing
	client.SetRetryConfig(RetryConfig{
		MaxRetries: 5,
		BaseDelay:  1 * time.Second,
		MaxDelay:   30 * time.Second,
	})

	tests := []struct {
		attempt  int
		expected time.Duration
	}{
		{0, 1 * time.Second},   // 1s * 2^0 = 1s
		{1, 2 * time.Second},   // 1s * 2^1 = 2s
		{2, 4 * time.Second},   // 1s * 2^2 = 4s
		{3, 8 * time.Second},   // 1s * 2^3 = 8s
		{4, 16 * time.Second},  // 1s * 2^4 = 16s
		{5, 30 * time.Second},  // 1s * 2^5 = 32s, capped at 30s
		{10, 30 * time.Second}, // Capped at max
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("attempt_%d", tt.attempt), func(t *testing.T) {
			delay := client.calculateBackoff(tt.attempt)
			if delay != tt.expected {
				t.Errorf("calculateBackoff(%d) = %v, want %v", tt.attempt, delay, tt.expected)
			}
		})
	}
}

func TestRetryOnConnectionFailure(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.PanicLevel)

	// Create client pointing to non-existent server
	client, err := NewClient(ClientConfig{
		BaseURL: "http://127.0.0.1:59998",
		Timeout: 50 * time.Millisecond,
	}, logger)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	// Set fast retry config for testing
	client.SetRetryConfig(RetryConfig{
		MaxRetries: 2,
		BaseDelay:  10 * time.Millisecond,
		MaxDelay:   50 * time.Millisecond,
	})

	start := time.Now()
	_, err = client.ListCertificates()
	elapsed := time.Since(start)

	// Should fail after retries
	if err == nil {
		t.Error("Expected connection error, got nil")
	}

	// Should have taken some time for retries (at least 2 retries with 10ms delays)
	if elapsed < 10*time.Millisecond {
		t.Errorf("Retries should have taken longer, elapsed: %v", elapsed)
	}

	// Error message should mention retry attempts
	if !strings.Contains(err.Error(), "after") {
		t.Errorf("Error should mention retry attempts: %v", err)
	}
}

func TestNoRetryWithZeroMaxRetries(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.PanicLevel)

	// Create client pointing to non-existent server
	client, err := NewClient(ClientConfig{
		BaseURL: "http://127.0.0.1:59997",
		Timeout: 50 * time.Millisecond,
	}, logger)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	// Set no retries
	client.SetRetryConfig(RetryConfig{
		MaxRetries: 0, // No retries
		BaseDelay:  10 * time.Millisecond,
		MaxDelay:   50 * time.Millisecond,
	})

	start := time.Now()
	_, err = client.ListCertificates()
	elapsed := time.Since(start)

	// Should fail immediately (no retries)
	if err == nil {
		t.Error("Expected connection error, got nil")
	}

	// Should be fast since no retries
	if elapsed > 500*time.Millisecond {
		t.Errorf("Should have failed quickly without retries, elapsed: %v", elapsed)
	}
}
