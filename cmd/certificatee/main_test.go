package main

import (
	"crypto/rand"
	"crypto/x509"
	"math/big"
	"testing"
	"time"

	"github.com/vinted/certificator/pkg/haproxy"
)

func TestEndsWith(t *testing.T) {
	tests := []struct {
		name     string
		s        string
		suffix   string
		expected bool
	}{
		{"empty strings", "", "", true},
		{"empty suffix", "hello", "", true},
		{"empty string with suffix", "", "x", false},
		{"exact match", "hello", "hello", true},
		{"suffix match", "hello", "lo", true},
		{"no match", "hello", "la", false},
		{"suffix longer than string", "lo", "hello", false},
		{"newline suffix", "hello\n", "\n", true},
		{"no newline suffix", "hello", "\n", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := endsWith(tt.s, tt.suffix)
			if result != tt.expected {
				t.Errorf("endsWith(%q, %q) = %v, want %v", tt.s, tt.suffix, result, tt.expected)
			}
		})
	}
}

func TestFormatSerial(t *testing.T) {
	tests := []struct {
		name     string
		serial   []byte
		expected string
	}{
		{"empty", []byte{}, ""},
		{"single byte", []byte{0x1f}, "1f"},
		{"multiple bytes", []byte{0x1f, 0x52, 0x02}, "1f5202"},
		{"leading zero byte", []byte{0x00, 0x1f}, "001f"},
		{"all zeros", []byte{0x00, 0x00}, "0000"},
		{"max bytes", []byte{0xff, 0xff}, "ffff"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatSerial(tt.serial)
			if result != tt.expected {
				t.Errorf("formatSerial(%v) = %q, want %q", tt.serial, result, tt.expected)
			}
		})
	}
}

func TestSerialsDiffer(t *testing.T) {
	// Create test certificates with specific serial numbers
	serial1 := big.NewInt(0x1f5202)
	serial2 := big.NewInt(0x1f5203)

	cert1 := &x509.Certificate{SerialNumber: serial1}
	cert2 := &x509.Certificate{SerialNumber: serial2}

	tests := []struct {
		name         string
		haproxyCert  *haproxy.CertInfo
		vaultCert    *x509.Certificate
		expectDiffer bool
	}{
		{
			name:         "nil haproxy cert",
			haproxyCert:  nil,
			vaultCert:    cert1,
			expectDiffer: true,
		},
		{
			name:         "nil vault cert",
			haproxyCert:  &haproxy.CertInfo{Serial: "1F5202"},
			vaultCert:    nil,
			expectDiffer: true,
		},
		{
			name:         "both nil",
			haproxyCert:  nil,
			vaultCert:    nil,
			expectDiffer: true,
		},
		{
			name:         "matching serials uppercase",
			haproxyCert:  &haproxy.CertInfo{Serial: "1F5202"},
			vaultCert:    cert1,
			expectDiffer: false,
		},
		{
			name:         "matching serials lowercase",
			haproxyCert:  &haproxy.CertInfo{Serial: "1f5202"},
			vaultCert:    cert1,
			expectDiffer: false,
		},
		{
			name:         "matching serials with colons",
			haproxyCert:  &haproxy.CertInfo{Serial: "1F:52:02"},
			vaultCert:    cert1,
			expectDiffer: false,
		},
		{
			name:         "different serials",
			haproxyCert:  &haproxy.CertInfo{Serial: "1F5202"},
			vaultCert:    cert2,
			expectDiffer: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := serialsDiffer(tt.haproxyCert, tt.vaultCert)
			if result != tt.expectDiffer {
				t.Errorf("serialsDiffer() = %v, want %v", result, tt.expectDiffer)
			}
		})
	}
}

func TestBuildPEMBundle(t *testing.T) {
	tests := []struct {
		name        string
		secrets     map[string]interface{}
		expectError bool
		expectPEM   string
	}{
		{
			name: "valid cert and key with newlines",
			secrets: map[string]interface{}{
				"certificate": "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n",
				"private_key": "-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----\n",
			},
			expectError: false,
			expectPEM:   "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----\n",
		},
		{
			name: "valid cert and key without trailing newline",
			secrets: map[string]interface{}{
				"certificate": "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----",
				"private_key": "-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----",
			},
			expectError: false,
			expectPEM:   "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----",
		},
		{
			name: "missing certificate",
			secrets: map[string]interface{}{
				"private_key": "-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----",
			},
			expectError: true,
		},
		{
			name: "missing private_key",
			secrets: map[string]interface{}{
				"certificate": "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----",
			},
			expectError: true,
		},
		{
			name:        "empty secrets",
			secrets:     map[string]interface{}{},
			expectError: true,
		},
		{
			name: "empty certificate value",
			secrets: map[string]interface{}{
				"certificate": "",
				"private_key": "-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----",
			},
			expectError: true,
		},
		{
			name: "empty private_key value",
			secrets: map[string]interface{}{
				"certificate": "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----",
				"private_key": "",
			},
			expectError: true,
		},
		{
			name: "wrong type for certificate",
			secrets: map[string]interface{}{
				"certificate": 12345,
				"private_key": "-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----",
			},
			expectError: true,
		},
		{
			name: "wrong type for private_key",
			secrets: map[string]interface{}{
				"certificate": "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----",
				"private_key": 12345,
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := buildPEMBundle(tt.secrets)
			if tt.expectError {
				if err == nil {
					t.Errorf("buildPEMBundle() expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("buildPEMBundle() unexpected error: %v", err)
				}
				if result != tt.expectPEM {
					t.Errorf("buildPEMBundle() = %q, want %q", result, tt.expectPEM)
				}
			}
		})
	}
}

func TestBuildPEMBundleWithRealCertFormat(t *testing.T) {
	// Test with realistic PEM format
	cert := `-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAJC1HiIAZAiUMA0GCSqGSIb3Qw0BBQUAMEUxCzAJBgNV
BAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX
aWRnaXRzIFB0eSBMdGQwHhcNMTExMjMxMDg1OTQ0WhcNMTIxMjMwMDg1OTQ0WjBF
-----END CERTIFICATE-----`

	//nolint:gosec // This is a test key, not a real credential
	key := `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0m59l2u9iDnMbrXHfqkOrn2dVQ3vfBJqcDuFUK03d+1PZGbV
-----END RSA PRIVATE KEY-----`

	secrets := map[string]interface{}{
		"certificate": cert,
		"private_key": key,
	}

	result, err := buildPEMBundle(secrets)
	if err != nil {
		t.Fatalf("buildPEMBundle() unexpected error: %v", err)
	}

	// Verify structure
	if !containsSubstring(result, "-----BEGIN CERTIFICATE-----") {
		t.Error("result should contain certificate header")
	}
	if !containsSubstring(result, "-----END CERTIFICATE-----") {
		t.Error("result should contain certificate footer")
	}
	if !containsSubstring(result, "-----BEGIN RSA PRIVATE KEY-----") {
		t.Error("result should contain private key header")
	}
	if !containsSubstring(result, "-----END RSA PRIVATE KEY-----") {
		t.Error("result should contain private key footer")
	}
}

// Helper function to check if string contains substring
func containsSubstring(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 || findSubstring(s, substr))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// Test that formatSerial works with actual x509 certificate serial numbers
func TestFormatSerialWithRandomSerial(t *testing.T) {
	// Generate a random serial number like a real CA would
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("failed to generate serial number: %v", err)
	}

	serialBytes := serialNumber.Bytes()
	result := formatSerial(serialBytes)

	// Verify the result is a valid hex string
	if len(result) == 0 && len(serialBytes) > 0 {
		t.Error("formatSerial should return non-empty string for non-empty bytes")
	}

	// Verify all characters are valid hex
	for _, c := range result {
		isDigit := c >= '0' && c <= '9'
		isHexLetter := c >= 'a' && c <= 'f'
		if !isDigit && !isHexLetter {
			t.Errorf("formatSerial returned invalid hex character: %c", c)
		}
	}
}

// Benchmark tests
func BenchmarkEndsWith(b *testing.B) {
	s := "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n"
	suffix := "\n"

	for i := 0; i < b.N; i++ {
		endsWith(s, suffix)
	}
}

func BenchmarkFormatSerial(b *testing.B) {
	serial := []byte{0x1f, 0x52, 0x02, 0xe0, 0x20, 0x83, 0x86, 0x1b, 0x30, 0x2f, 0xfa, 0x09, 0x04, 0x57, 0x21, 0xf0, 0x7c, 0x86, 0x5e, 0xfd}

	for i := 0; i < b.N; i++ {
		formatSerial(serial)
	}
}

func BenchmarkBuildPEMBundle(b *testing.B) {
	secrets := map[string]interface{}{
		"certificate": "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n",
		"private_key": "-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----\n",
	}

	for i := 0; i < b.N; i++ {
		_, _ = buildPEMBundle(secrets)
	}
}

// Test edge cases for time-based logic (used in shouldUpdateCertificate)
func TestCertificateExpiryLogic(t *testing.T) {
	// Test IsExpiring function from haproxy package
	now := time.Now()

	tests := []struct {
		name            string
		notAfter        time.Time
		renewBeforeDays int
		expectExpiring  bool
	}{
		{
			name:            "expired certificate",
			notAfter:        now.AddDate(0, 0, -1),
			renewBeforeDays: 30,
			expectExpiring:  true,
		},
		{
			name:            "expiring within threshold",
			notAfter:        now.AddDate(0, 0, 15),
			renewBeforeDays: 30,
			expectExpiring:  true,
		},
		{
			name:            "expiring at threshold",
			notAfter:        now.AddDate(0, 0, 30),
			renewBeforeDays: 30,
			expectExpiring:  true,
		},
		{
			name:            "not expiring",
			notAfter:        now.AddDate(0, 0, 60),
			renewBeforeDays: 30,
			expectExpiring:  false,
		},
		{
			name:            "zero threshold",
			notAfter:        now.AddDate(0, 0, 1),
			renewBeforeDays: 0,
			expectExpiring:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			certInfo := &haproxy.CertInfo{
				NotAfter: tt.notAfter,
			}
			result := haproxy.IsExpiring(certInfo, tt.renewBeforeDays)
			if result != tt.expectExpiring {
				t.Errorf("IsExpiring() = %v, want %v (notAfter: %v, threshold: %d days)",
					result, tt.expectExpiring, tt.notAfter, tt.renewBeforeDays)
			}
		})
	}
}
