package haproxy

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

// =============================================================================
// Unit Tests for Parsing Functions
// =============================================================================

func TestParseCertInfo(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantErr   bool
		checkFunc func(t *testing.T, info *CertInfo)
	}{
		{
			name: "valid complete response",
			input: `Filename: /etc/haproxy/certs/example.com.pem
Status: Used
Serial: 1F5202E02083861B302FFA09045721F07C865EFD
notBefore: Aug 12 17:05:34 2020 GMT
notAfter: Aug 12 17:05:34 2021 GMT
Subject Alternative Name: DNS:example.com, DNS:www.example.com
Algorithm: RSA2048
SHA1 FingerPrint: C2958E4ABDF89447BF0BEDEF43A1A202213B7B4C
Subject: /C=US/ST=Ohio/L=Columbus/O=Company/CN=example.local
Issuer: /C=US/O=Let's Encrypt/CN=R3`,
			wantErr: false,
			checkFunc: func(t *testing.T, info *CertInfo) {
				if info.Filename != "/etc/haproxy/certs/example.com.pem" {
					t.Errorf("Filename = %q, want %q", info.Filename, "/etc/haproxy/certs/example.com.pem")
				}
				if info.Status != "Used" {
					t.Errorf("Status = %q, want %q", info.Status, "Used")
				}
				if info.Serial != "1F5202E02083861B302FFA09045721F07C865EFD" {
					t.Errorf("Serial = %q, want %q", info.Serial, "1F5202E02083861B302FFA09045721F07C865EFD")
				}
				if info.Algorithm != "RSA2048" {
					t.Errorf("Algorithm = %q, want %q", info.Algorithm, "RSA2048")
				}
				if len(info.SANs) != 2 {
					t.Errorf("SANs length = %d, want 2", len(info.SANs))
				}
				if info.NotAfter.Year() != 2021 {
					t.Errorf("NotAfter year = %d, want 2021", info.NotAfter.Year())
				}
			},
		},
		{
			name: "minimal valid response",
			input: `Filename: /etc/haproxy/certs/site.pem
Serial: ABC123`,
			wantErr: false,
			checkFunc: func(t *testing.T, info *CertInfo) {
				if info.Filename != "/etc/haproxy/certs/site.pem" {
					t.Errorf("Filename = %q, want %q", info.Filename, "/etc/haproxy/certs/site.pem")
				}
				if info.Serial != "ABC123" {
					t.Errorf("Serial = %q, want %q", info.Serial, "ABC123")
				}
			},
		},
		{
			name:    "empty response",
			input:   "",
			wantErr: true,
		},
		{
			name:    "no filename or serial",
			input:   "Status: Used\nAlgorithm: RSA2048",
			wantErr: true,
		},
		{
			name: "response with extra whitespace",
			input: `  Filename:   /etc/haproxy/certs/site.pem  
  Serial:   ABC123  `,
			wantErr: false,
			checkFunc: func(t *testing.T, info *CertInfo) {
				if info.Filename != "/etc/haproxy/certs/site.pem" {
					t.Errorf("Filename = %q, want %q", info.Filename, "/etc/haproxy/certs/site.pem")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info, err := parseCertInfo(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseCertInfo() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && tt.checkFunc != nil {
				tt.checkFunc(t, info)
			}
		})
	}
}

func TestParseHAProxyTime(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
		check   func(t *testing.T, tm time.Time)
	}{
		{
			name:    "double digit day",
			input:   "Aug 12 17:05:34 2020 GMT",
			wantErr: false,
			check: func(t *testing.T, tm time.Time) {
				if tm.Day() != 12 || tm.Month() != time.August || tm.Year() != 2020 {
					t.Errorf("got %v, want Aug 12 2020", tm)
				}
			},
		},
		{
			name:    "single digit day",
			input:   "Aug 2 17:05:34 2020 GMT",
			wantErr: false,
			check: func(t *testing.T, tm time.Time) {
				if tm.Day() != 2 {
					t.Errorf("Day = %d, want 2", tm.Day())
				}
			},
		},
		{
			name:    "january date",
			input:   "Jan 15 00:00:00 2025 GMT",
			wantErr: false,
			check: func(t *testing.T, tm time.Time) {
				if tm.Month() != time.January || tm.Year() != 2025 {
					t.Errorf("got %v, want Jan 2025", tm)
				}
			},
		},
		{
			name:    "invalid format",
			input:   "2020-08-12T17:05:34Z",
			wantErr: true,
		},
		{
			name:    "empty string",
			input:   "",
			wantErr: true,
		},
		{
			name:    "garbage",
			input:   "not a date",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tm, err := parseHAProxyTime(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseHAProxyTime(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if !tt.wantErr && tt.check != nil {
				tt.check(t, tm)
			}
		})
	}
}

func TestParseSANs(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "multiple SANs with DNS prefix",
			input: "DNS:example.com, DNS:www.example.com",
			want:  []string{"example.com", "www.example.com"},
		},
		{
			name:  "single SAN",
			input: "DNS:example.com",
			want:  []string{"example.com"},
		},
		{
			name:  "empty string",
			input: "",
			want:  nil,
		},
		{
			name:  "without DNS prefix",
			input: "example.com, www.example.com",
			want:  []string{"example.com", "www.example.com"},
		},
		{
			name:  "mixed with and without prefix",
			input: "DNS:example.com, www.example.com",
			want:  []string{"example.com", "www.example.com"},
		},
		{
			name:  "extra whitespace",
			input: "  DNS:example.com  ,   DNS:www.example.com  ",
			want:  []string{"example.com", "www.example.com"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseSANs(tt.input)
			if len(got) != len(tt.want) {
				t.Errorf("parseSANs(%q) = %v, want %v", tt.input, got, tt.want)
				return
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("parseSANs(%q)[%d] = %q, want %q", tt.input, i, got[i], tt.want[i])
				}
			}
		})
	}
}

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

// =============================================================================
// Unit Tests for Client Constructors
// =============================================================================

func TestNewClient(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.PanicLevel) // Suppress logs in tests

	tests := []struct {
		name        string
		endpoint    string
		wantErr     bool
		wantNetwork string
	}{
		{
			name:     "empty endpoint",
			endpoint: "",
			wantErr:  true,
		},
		{
			name:        "unix socket path",
			endpoint:    "/var/run/haproxy.sock",
			wantErr:     false,
			wantNetwork: "unix",
		},
		{
			name:        "tcp address",
			endpoint:    "127.0.0.1:9999",
			wantErr:     false,
			wantNetwork: "tcp",
		},
		{
			name:        "tcp address with hostname",
			endpoint:    "haproxy.local:9999",
			wantErr:     false,
			wantNetwork: "tcp",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewClient(tt.endpoint, logger)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewClient() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if client.network != tt.wantNetwork {
					t.Errorf("client.network = %q, want %q", client.network, tt.wantNetwork)
				}
				if client.endpoint != tt.endpoint {
					t.Errorf("client.endpoint = %q, want %q", client.endpoint, tt.endpoint)
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
		endpoints []string
		wantErr   bool
		wantCount int
	}{
		{
			name:      "empty slice",
			endpoints: []string{},
			wantErr:   true,
		},
		{
			name:      "nil slice",
			endpoints: nil,
			wantErr:   true,
		},
		{
			name:      "single endpoint",
			endpoints: []string{"/var/run/haproxy.sock"},
			wantErr:   false,
			wantCount: 1,
		},
		{
			name:      "multiple endpoints",
			endpoints: []string{"/var/run/haproxy1.sock", "/var/run/haproxy2.sock", "127.0.0.1:9999"},
			wantErr:   false,
			wantCount: 3,
		},
		{
			name:      "with empty strings",
			endpoints: []string{"/var/run/haproxy.sock", "", "  ", "127.0.0.1:9999"},
			wantErr:   false,
			wantCount: 2, // empty strings are skipped
		},
		{
			name:      "only empty strings",
			endpoints: []string{"", "  ", "   "},
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clients, err := NewClients(tt.endpoints, logger)
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

	client, err := NewClient("/var/run/haproxy.sock", logger)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	if got := client.Endpoint(); got != "/var/run/haproxy.sock" {
		t.Errorf("Endpoint() = %q, want %q", got, "/var/run/haproxy.sock")
	}
}

// =============================================================================
// Mock HAProxy Server for Integration Tests
// =============================================================================

// mockHAProxyServer simulates the HAProxy Runtime API
type mockHAProxyServer struct {
	listener  net.Listener
	responses map[string]string // command prefix -> response
	t         *testing.T
}

// newMockHAProxyServer creates a mock server listening on a random TCP port
func newMockHAProxyServer(t *testing.T) *mockHAProxyServer {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create mock server: %v", err)
	}

	m := &mockHAProxyServer{
		listener:  listener,
		responses: make(map[string]string),
		t:         t,
	}

	go m.serve()
	return m
}

func (m *mockHAProxyServer) serve() {
	for {
		conn, err := m.listener.Accept()
		if err != nil {
			return // Server closed
		}
		go m.handleConnection(conn)
	}
}

func (m *mockHAProxyServer) handleConnection(conn net.Conn) {
	defer func() { _ = conn.Close() }()

	// Set a read deadline to prevent hanging
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	reader := bufio.NewReader(conn)

	// Read the first line to determine command type
	firstLine, err := reader.ReadString('\n')
	if err != nil {
		return
	}

	var cmd string

	// For "set ssl cert" commands, we need to read the multiline PEM data
	if strings.HasPrefix(strings.TrimSpace(firstLine), "set ssl cert") {
		// Read until we see the end marker (empty line after PEM data)
		var fullCmd strings.Builder
		fullCmd.WriteString(firstLine)

		// Read all remaining data with a short timeout
		_ = conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				break
			}
			fullCmd.WriteString(line)
		}
		cmd = fullCmd.String()
	} else {
		cmd = firstLine
	}

	// Find matching response
	response := "Unknown command\n"
	for prefix, resp := range m.responses {
		if strings.HasPrefix(strings.TrimSpace(cmd), prefix) {
			response = resp
			break
		}
	}

	_, _ = conn.Write([]byte(response))
}

func (m *mockHAProxyServer) Addr() string {
	return m.listener.Addr().String()
}

func (m *mockHAProxyServer) Close() {
	_ = m.listener.Close()
}

func (m *mockHAProxyServer) SetResponse(commandPrefix, response string) {
	m.responses[commandPrefix] = response
}

// =============================================================================
// Integration Tests
// =============================================================================

func TestListCertificates(t *testing.T) {
	mock := newMockHAProxyServer(t)
	defer mock.Close()

	logger := logrus.New()
	logger.SetLevel(logrus.PanicLevel)

	tests := []struct {
		name     string
		response string
		want     []string
		wantErr  bool
	}{
		{
			name: "normal response with multiple certs",
			response: `# transaction
*/etc/haproxy/certs/pending.pem
# filename
/etc/haproxy/certs/site1.pem
/etc/haproxy/certs/site2.pem
`,
			want:    []string{"/etc/haproxy/certs/site1.pem", "/etc/haproxy/certs/site2.pem"},
			wantErr: false,
		},
		{
			name:     "empty response",
			response: "\n",
			want:     nil,
			wantErr:  false,
		},
		{
			name: "only comments and transactions",
			response: `# comment
*/etc/haproxy/certs/pending.pem
# another comment
`,
			want:    nil,
			wantErr: false,
		},
		{
			name: "single certificate",
			response: `/etc/haproxy/certs/only.pem
`,
			want:    []string{"/etc/haproxy/certs/only.pem"},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock.SetResponse("show ssl cert", tt.response)

			client, err := NewClient(mock.Addr(), logger)
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
	mock := newMockHAProxyServer(t)
	defer mock.Close()

	logger := logrus.New()
	logger.SetLevel(logrus.PanicLevel)

	validResponse := `Filename: /etc/haproxy/certs/example.com.pem
Status: Used
Serial: ABC123DEF456
notBefore: Jan 1 00:00:00 2024 GMT
notAfter: Dec 31 23:59:59 2024 GMT
Subject Alternative Name: DNS:example.com, DNS:www.example.com
Algorithm: RSA2048
SHA1 FingerPrint: AABBCCDD
Subject: /CN=example.com
Issuer: /CN=Test CA
`

	tests := []struct {
		name      string
		certPath  string
		response  string
		wantErr   bool
		checkFunc func(t *testing.T, info *CertInfo)
	}{
		{
			name:     "valid certificate info",
			certPath: "/etc/haproxy/certs/example.com.pem",
			response: validResponse,
			wantErr:  false,
			checkFunc: func(t *testing.T, info *CertInfo) {
				if info.Serial != "ABC123DEF456" {
					t.Errorf("Serial = %q, want %q", info.Serial, "ABC123DEF456")
				}
				if len(info.SANs) != 2 {
					t.Errorf("SANs count = %d, want 2", len(info.SANs))
				}
			},
		},
		{
			name:     "certificate not found",
			certPath: "/etc/haproxy/certs/notfound.pem",
			response: "Can't display transaction for a certificate without storage.\n",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock.SetResponse(fmt.Sprintf("show ssl cert %s", tt.certPath), tt.response)

			client, err := NewClient(mock.Addr(), logger)
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

func TestSetCertificate(t *testing.T) {
	mock := newMockHAProxyServer(t)
	defer mock.Close()

	logger := logrus.New()
	logger.SetLevel(logrus.PanicLevel)

	tests := []struct {
		name     string
		certPath string
		pemData  string
		response string
		wantErr  bool
	}{
		{
			name:     "success - transaction created",
			certPath: "/etc/haproxy/certs/example.com.pem",
			pemData:  "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
			response: "Transaction created for certificate /etc/haproxy/certs/example.com.pem!\n",
			wantErr:  false,
		},
		{
			name:     "success - transaction updated",
			certPath: "/etc/haproxy/certs/example.com.pem",
			pemData:  "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
			response: "transaction updated for certificate /etc/haproxy/certs/example.com.pem!\n",
			wantErr:  false,
		},
		{
			name:     "error - certificate not found",
			certPath: "/etc/haproxy/certs/notfound.pem",
			pemData:  "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
			response: "error: certificate not found\n",
			wantErr:  true,
		},
		{
			name:     "error - unable to parse",
			certPath: "/etc/haproxy/certs/bad.pem",
			pemData:  "invalid pem",
			response: "unable to parse certificate\n",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock.SetResponse("set ssl cert", tt.response)

			client, err := NewClient(mock.Addr(), logger)
			if err != nil {
				t.Fatalf("NewClient() error = %v", err)
			}

			err = client.SetCertificate(tt.certPath, tt.pemData)
			if (err != nil) != tt.wantErr {
				t.Errorf("SetCertificate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestCommitCertificate(t *testing.T) {
	mock := newMockHAProxyServer(t)
	defer mock.Close()

	logger := logrus.New()
	logger.SetLevel(logrus.PanicLevel)

	tests := []struct {
		name     string
		certPath string
		response string
		wantErr  bool
	}{
		{
			name:     "success",
			certPath: "/etc/haproxy/certs/example.com.pem",
			response: "Committing /etc/haproxy/certs/example.com.pem\nSuccess!\n",
			wantErr:  false,
		},
		{
			name:     "error - no transaction",
			certPath: "/etc/haproxy/certs/notfound.pem",
			response: "error: no transaction for certificate\n",
			wantErr:  true,
		},
		{
			name:     "error - failed",
			certPath: "/etc/haproxy/certs/bad.pem",
			response: "failed to commit certificate\n",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock.SetResponse("commit ssl cert", tt.response)

			client, err := NewClient(mock.Addr(), logger)
			if err != nil {
				t.Fatalf("NewClient() error = %v", err)
			}

			err = client.CommitCertificate(tt.certPath)
			if (err != nil) != tt.wantErr {
				t.Errorf("CommitCertificate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestUpdateCertificate(t *testing.T) {
	mock := newMockHAProxyServer(t)
	defer mock.Close()

	logger := logrus.New()
	logger.SetLevel(logrus.PanicLevel)

	t.Run("success - set and commit", func(t *testing.T) {
		mock.SetResponse("set ssl cert", "Transaction created for certificate /etc/haproxy/certs/example.com.pem!\n")
		mock.SetResponse("commit ssl cert", "Committing /etc/haproxy/certs/example.com.pem\nSuccess!\n")

		client, err := NewClient(mock.Addr(), logger)
		if err != nil {
			t.Fatalf("NewClient() error = %v", err)
		}

		err = client.UpdateCertificate("/etc/haproxy/certs/example.com.pem", "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----")
		if err != nil {
			t.Errorf("UpdateCertificate() error = %v", err)
		}
	})

	t.Run("failure - set fails", func(t *testing.T) {
		mock.SetResponse("set ssl cert", "error: certificate not found\n")

		client, err := NewClient(mock.Addr(), logger)
		if err != nil {
			t.Fatalf("NewClient() error = %v", err)
		}

		err = client.UpdateCertificate("/etc/haproxy/certs/notfound.pem", "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----")
		if err == nil {
			t.Error("UpdateCertificate() expected error, got nil")
		}
	})

	t.Run("failure - commit fails", func(t *testing.T) {
		mock.SetResponse("set ssl cert", "Transaction created for certificate /etc/haproxy/certs/example.com.pem!\n")
		mock.SetResponse("commit ssl cert", "failed to commit certificate\n")

		client, err := NewClient(mock.Addr(), logger)
		if err != nil {
			t.Fatalf("NewClient() error = %v", err)
		}

		err = client.UpdateCertificate("/etc/haproxy/certs/example.com.pem", "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----")
		if err == nil {
			t.Error("UpdateCertificate() expected error, got nil")
		}
	})
}

func TestAbortCertificate(t *testing.T) {
	mock := newMockHAProxyServer(t)
	defer mock.Close()

	logger := logrus.New()
	logger.SetLevel(logrus.PanicLevel)

	mock.SetResponse("abort ssl cert", "Transaction aborted for certificate /etc/haproxy/certs/example.com.pem!\n")

	client, err := NewClient(mock.Addr(), logger)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	err = client.AbortCertificate("/etc/haproxy/certs/example.com.pem")
	if err != nil {
		t.Errorf("AbortCertificate() error = %v", err)
	}
}

// =============================================================================
// Connection Error Tests
// =============================================================================

func TestConnectionError(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.PanicLevel)

	// Create client pointing to non-existent server
	client, err := NewClient("127.0.0.1:59999", logger)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	// Reduce timeout and disable retries for faster test
	client.timeout = 100 * time.Millisecond
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

	client, err := NewClient("127.0.0.1:9999", logger)
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

	client, err := NewClient("127.0.0.1:9999", logger)
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
	client, err := NewClient("127.0.0.1:59998", logger)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	// Set fast retry config for testing
	client.timeout = 50 * time.Millisecond
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
	client, err := NewClient("127.0.0.1:59997", logger)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	// Set no retries
	client.timeout = 50 * time.Millisecond
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

func TestRetrySucceedsOnSecondAttempt(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.PanicLevel)

	// Start mock server after a delay (simulating server becoming available)
	var mock *mockHAProxyServer
	serverStarted := make(chan struct{})

	go func() {
		time.Sleep(100 * time.Millisecond)
		mock = newMockHAProxyServer(t)
		mock.SetResponse("show ssl cert", "/etc/haproxy/certs/test.pem\n")
		serverStarted <- struct{}{}
	}()

	// Wait for server to start
	<-serverStarted
	defer mock.Close()

	client, err := NewClient(mock.Addr(), logger)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	// Should succeed now that server is up
	certs, err := client.ListCertificates()
	if err != nil {
		t.Errorf("ListCertificates() error = %v", err)
	}
	if len(certs) != 1 || certs[0] != "/etc/haproxy/certs/test.pem" {
		t.Errorf("ListCertificates() = %v, want [/etc/haproxy/certs/test.pem]", certs)
	}
}

// =============================================================================
// Command Name Extraction Tests
// =============================================================================

func TestExtractCommandName(t *testing.T) {
	tests := []struct {
		command  string
		expected string
	}{
		{"show ssl cert", "show ssl"},
		{"show ssl cert /path/to/cert.pem", "show ssl"},
		{"set ssl cert /path/to/cert.pem <<\nPEM DATA", "set ssl"},
		{"commit ssl cert /path/to/cert.pem", "commit ssl"},
		{"abort ssl cert /path/to/cert.pem", "abort ssl"},
		{"show info", "show info"},
		{"help", "help"},
		{"", "unknown"},
		{"   show ssl cert   ", "show ssl"},
	}

	for _, tt := range tests {
		t.Run(tt.command, func(t *testing.T) {
			got := extractCommandName(tt.command)
			if got != tt.expected {
				t.Errorf("extractCommandName(%q) = %q, want %q", tt.command, got, tt.expected)
			}
		})
	}
}
