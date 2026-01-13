package haproxy

import (
	"bufio"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// CertInfo holds certificate information parsed from HAProxy Runtime API
type CertInfo struct {
	Filename  string
	Status    string
	Serial    string
	NotBefore time.Time
	NotAfter  time.Time
	Subject   string
	Issuer    string
	Algorithm string
	SHA1      string
	SANs      []string
}

// Client is a HAProxy Runtime API client
type Client struct {
	endpoint string
	network  string // "unix" or "tcp"
	timeout  time.Duration
	logger   *logrus.Logger
}

// NewClient creates a new HAProxy Runtime API client from an endpoint string
// The endpoint can be either:
//   - A Unix socket path (starts with /): e.g., "/var/run/haproxy.sock"
//   - A TCP address (host:port): e.g., "127.0.0.1:9999"
func NewClient(endpoint string, logger *logrus.Logger) (*Client, error) {
	if endpoint == "" {
		return nil, errors.New("endpoint must be provided")
	}

	network := "tcp"
	if strings.HasPrefix(endpoint, "/") {
		network = "unix"
	}

	return &Client{
		endpoint: endpoint,
		network:  network,
		timeout:  30 * time.Second,
		logger:   logger,
	}, nil
}

// NewClients creates multiple HAProxy Runtime API clients from a list of endpoints
func NewClients(endpoints []string, logger *logrus.Logger) ([]*Client, error) {
	if len(endpoints) == 0 {
		return nil, errors.New("at least one endpoint must be provided")
	}

	clients := make([]*Client, 0, len(endpoints))
	for _, endpoint := range endpoints {
		endpoint = strings.TrimSpace(endpoint)
		if endpoint == "" {
			continue
		}
		client, err := NewClient(endpoint, logger)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to create client for endpoint %s", endpoint)
		}
		clients = append(clients, client)
	}

	if len(clients) == 0 {
		return nil, errors.New("no valid endpoints provided")
	}

	return clients, nil
}

// Endpoint returns the endpoint address of this client
func (c *Client) Endpoint() string {
	return c.endpoint
}

// dial establishes a connection to HAProxy Runtime API
func (c *Client) dial() (net.Conn, error) {
	conn, err := net.DialTimeout(c.network, c.endpoint, c.timeout)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to connect to HAProxy at %s", c.endpoint)
	}
	return conn, nil
}

// execute sends a command to HAProxy Runtime API and returns the response
func (c *Client) execute(command string) (string, error) {
	conn, err := c.dial()
	if err != nil {
		return "", err
	}
	defer conn.Close()

	// Set read/write deadline
	if err := conn.SetDeadline(time.Now().Add(c.timeout)); err != nil {
		return "", errors.Wrap(err, "failed to set connection deadline")
	}

	// Send command (must end with newline)
	if !strings.HasSuffix(command, "\n") {
		command += "\n"
	}

	_, err = conn.Write([]byte(command))
	if err != nil {
		return "", errors.Wrapf(err, "failed to send command: %s", command)
	}

	// Read response
	var response strings.Builder
	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		response.WriteString(scanner.Text())
		response.WriteString("\n")
	}

	if err := scanner.Err(); err != nil {
		return "", errors.Wrap(err, "failed to read response")
	}

	return response.String(), nil
}

// ListCertificates returns a list of certificate paths loaded in HAProxy
func (c *Client) ListCertificates() ([]string, error) {
	response, err := c.execute("show ssl cert")
	if err != nil {
		return nil, err
	}

	var certs []string
	lines := strings.Split(response, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Skip transaction entries (prefixed with *)
		if strings.HasPrefix(line, "*") {
			continue
		}
		certs = append(certs, line)
	}

	return certs, nil
}

// GetCertificateInfo retrieves detailed information about a specific certificate
func (c *Client) GetCertificateInfo(certPath string) (*CertInfo, error) {
	response, err := c.execute(fmt.Sprintf("show ssl cert %s", certPath))
	if err != nil {
		return nil, err
	}

	return parseCertInfo(response)
}

// parseCertInfo parses the output of "show ssl cert <path>"
// Example output:
//
//	Filename: /etc/haproxy/certs/site.pem
//	Status: Used
//	Serial: 1F5202E02083861B302FFA09045721F07C865EFD
//	notBefore: Aug 12 17:05:34 2020 GMT
//	notAfter: Aug 12 17:05:34 2021 GMT
//	Subject Alternative Name: DNS:example.com, DNS:www.example.com
//	Algorithm: RSA2048
//	SHA1 FingerPrint: C2958E4ABDF89447BF0BEDEF43A1A202213B7B4C
//	Subject: /C=US/ST=Ohio/L=Columbus/O=Company/CN=example.local
//	Issuer: /C=US/O=Let's Encrypt/CN=R3
func parseCertInfo(response string) (*CertInfo, error) {
	info := &CertInfo{}
	lines := strings.Split(response, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Split on first colon
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		switch key {
		case "Filename":
			info.Filename = value
		case "Status":
			info.Status = value
		case "Serial":
			info.Serial = value
		case "notBefore":
			t, err := parseHAProxyTime(value)
			if err == nil {
				info.NotBefore = t
			}
		case "notAfter":
			t, err := parseHAProxyTime(value)
			if err == nil {
				info.NotAfter = t
			}
		case "Subject Alternative Name":
			info.SANs = parseSANs(value)
		case "Algorithm":
			info.Algorithm = value
		case "SHA1 FingerPrint":
			info.SHA1 = value
		case "Subject":
			info.Subject = value
		case "Issuer":
			info.Issuer = value
		}
	}

	if info.Filename == "" && info.Serial == "" {
		return nil, errors.New("failed to parse certificate info: no filename or serial found")
	}

	return info, nil
}

// parseHAProxyTime parses time in HAProxy format: "Aug 12 17:05:34 2020 GMT"
func parseHAProxyTime(s string) (time.Time, error) {
	// HAProxy uses format: "Jan 02 15:04:05 2006 MST"
	// Try multiple formats as HAProxy may vary slightly
	formats := []string{
		"Jan 2 15:04:05 2006 MST",
		"Jan 02 15:04:05 2006 MST",
		"Jan _2 15:04:05 2006 MST",
	}

	for _, format := range formats {
		t, err := time.Parse(format, s)
		if err == nil {
			return t, nil
		}
	}

	return time.Time{}, fmt.Errorf("failed to parse time: %s", s)
}

// parseSANs parses Subject Alternative Names from HAProxy format
// Example: "DNS:example.com, DNS:www.example.com"
func parseSANs(s string) []string {
	var sans []string
	parts := strings.Split(s, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		// Remove DNS: prefix if present
		if strings.HasPrefix(part, "DNS:") {
			part = strings.TrimPrefix(part, "DNS:")
		}
		if part != "" {
			sans = append(sans, part)
		}
	}
	return sans
}

// SetCertificate uploads a new certificate to HAProxy (starts a transaction)
// The pemData should contain the full PEM bundle (certificate + private key)
func (c *Client) SetCertificate(certPath, pemData string) error {
	// HAProxy expects the certificate in a heredoc-style format:
	// set ssl cert /path/to/cert.pem <<
	// <PEM data>
	//
	// The empty line at the end signals end of data
	command := fmt.Sprintf("set ssl cert %s <<\n%s\n", certPath, pemData)

	response, err := c.execute(command)
	if err != nil {
		return errors.Wrapf(err, "failed to set certificate %s", certPath)
	}

	// Check for success message
	response = strings.TrimSpace(response)
	if !strings.Contains(response, "Transaction created") && !strings.Contains(response, "transaction updated") {
		// Check if it's an error
		if strings.Contains(strings.ToLower(response), "error") ||
			strings.Contains(strings.ToLower(response), "failed") ||
			strings.Contains(strings.ToLower(response), "unable") {
			return errors.Errorf("failed to set certificate %s: %s", certPath, response)
		}
	}

	c.logger.Debugf("Set certificate %s: %s", certPath, response)
	return nil
}

// CommitCertificate commits a certificate transaction
func (c *Client) CommitCertificate(certPath string) error {
	response, err := c.execute(fmt.Sprintf("commit ssl cert %s", certPath))
	if err != nil {
		return errors.Wrapf(err, "failed to commit certificate %s", certPath)
	}

	response = strings.TrimSpace(response)
	// Check for success
	if !strings.Contains(response, "Success") && !strings.Contains(response, "Committing") {
		if strings.Contains(strings.ToLower(response), "error") ||
			strings.Contains(strings.ToLower(response), "failed") {
			return errors.Errorf("failed to commit certificate %s: %s", certPath, response)
		}
	}

	c.logger.Debugf("Committed certificate %s: %s", certPath, response)
	return nil
}

// UpdateCertificate uploads and commits a certificate update in one operation
func (c *Client) UpdateCertificate(certPath, pemData string) error {
	if err := c.SetCertificate(certPath, pemData); err != nil {
		return err
	}

	if err := c.CommitCertificate(certPath); err != nil {
		return err
	}

	return nil
}

// AbortCertificate aborts a pending certificate transaction
func (c *Client) AbortCertificate(certPath string) error {
	response, err := c.execute(fmt.Sprintf("abort ssl cert %s", certPath))
	if err != nil {
		return errors.Wrapf(err, "failed to abort certificate transaction %s", certPath)
	}

	c.logger.Debugf("Aborted certificate %s: %s", certPath, response)
	return nil
}

// ExtractDomainFromPath extracts the domain name from a certificate path
// Example: /etc/haproxy/certs/example.com.pem -> example.com
func ExtractDomainFromPath(certPath string) string {
	// Get the filename
	parts := strings.Split(certPath, "/")
	filename := parts[len(parts)-1]

	// Remove common extensions
	extensions := []string{".pem", ".crt", ".cert", ".cer"}
	for _, ext := range extensions {
		if strings.HasSuffix(filename, ext) {
			filename = strings.TrimSuffix(filename, ext)
			break
		}
	}

	return filename
}

// IsExpiring checks if a certificate is expiring within the given number of days
func IsExpiring(certInfo *CertInfo, renewBeforeDays int) bool {
	if certInfo == nil {
		return true
	}

	threshold := time.Now().AddDate(0, 0, renewBeforeDays)
	return certInfo.NotAfter.Before(threshold)
}

// NormalizeSerial normalizes a certificate serial number for comparison
// Removes colons, spaces, and converts to uppercase
func NormalizeSerial(serial string) string {
	re := regexp.MustCompile(`[^a-fA-F0-9]`)
	return strings.ToUpper(re.ReplaceAllString(serial, ""))
}
