package haproxy

import (
	"strings"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

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
			name: "valid configs",
			configs: []ClientConfig{
				{BaseURL: "http://haproxy1:5555", Username: "admin", Password: "secret"},
				{BaseURL: "http://haproxy2:5555", Username: "admin", Password: "secret"},
				{BaseURL: "http://haproxy3:5555", Username: "admin", Password: "secret"},
			},
			wantErr:   false,
			wantCount: 3,
		},
		{
			name: "some invalid configs",
			configs: []ClientConfig{
				{BaseURL: "http://haproxy1:5555", Username: "admin", Password: "secret"},
				{BaseURL: ""},
				{BaseURL: "http://haproxy2:5555", Username: "admin", Password: "secret"},
			},
			wantErr:   false,
			wantCount: 2,
		},
		{
			name: "all invalid configs",
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
				t.Errorf("NewClients() got %d clients, want %d", len(clients), tt.wantCount)
			}
		})
	}
}

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

	_, err = client.ListCertificates()
	if err == nil {
		t.Error("Expected error for connection, got nil")
	}
}
