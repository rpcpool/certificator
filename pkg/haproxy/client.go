package haproxy

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/hashicorp/go-retryablehttp"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// CertInfo holds certificate information from HAProxy Data Plane API
type CertInfo struct {
	Filename     string    `json:"file"`
	StorageName  string    `json:"storage_name"`
	Status       string    `json:"status"`
	Serial       string    `json:"serial"`
	NotBefore    time.Time `json:"-"`
	NotBeforeStr string    `json:"not_before"`
	NotAfter     time.Time `json:"-"`
	NotAfterStr  string    `json:"not_after"`
	Subject      string    `json:"subject"`
	Issuer       string    `json:"issuer"`
	Algorithm    string    `json:"algorithm"`
	SHA1         string    `json:"sha1_fingerprint"`
	SANs         []string  `json:"subject_alternative_names"`
}

// Client is a HAProxy Data Plane API client
type Client struct {
	baseURL    string
	username   string
	password   string
	httpClient *http.Client
	logger     *logrus.Logger
	timeout    time.Duration
}

// ClientConfig holds configuration for creating a new Client
type ClientConfig struct {
	BaseURL            string
	Username           string
	Password           string
	InsecureSkipVerify bool
	Timeout            time.Duration
}

// NewClient creates a new HAProxy Data Plane API client
func NewClient(cfg ClientConfig, logger *logrus.Logger) (*Client, error) {
	if cfg.BaseURL == "" {
		return nil, errors.New("baseURL must be provided")
	}

	// Ensure baseURL doesn't have trailing slash
	cfg.BaseURL = strings.TrimSuffix(cfg.BaseURL, "/")

	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: cfg.InsecureSkipVerify, //nolint:gosec // User-configurable
		},
	}

	httpClient := retryablehttp.NewClient()
	httpClient.Logger = &logrusLeveledLogger{logger: logger}
	httpClient.HTTPClient.Transport = transport
	httpClient.HTTPClient.Timeout = timeout

	return &Client{
		baseURL:    cfg.BaseURL,
		username:   cfg.Username,
		password:   cfg.Password,
		httpClient: httpClient.StandardClient(),
		logger:     logger,
		timeout:    timeout,
	}, nil
}

// NewClients creates multiple HAProxy Data Plane API clients from a list of configurations
func NewClients(configs []ClientConfig, logger *logrus.Logger) ([]*Client, error) {
	if len(configs) == 0 {
		return nil, errors.New("at least one endpoint configuration must be provided")
	}

	clients := make([]*Client, 0, len(configs))
	for _, cfg := range configs {
		if cfg.BaseURL == "" {
			continue
		}
		client, err := NewClient(cfg, logger)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to create client for endpoint %s", cfg.BaseURL)
		}
		clients = append(clients, client)
	}

	if len(clients) == 0 {
		return nil, errors.New("no valid endpoint configurations provided")
	}

	return clients, nil
}

// Endpoint returns the endpoint address of this client
func (c *Client) Endpoint() string {
	return c.baseURL
}

// doRequest performs an HTTP request with retry logic
func (c *Client) doRequest(method, path string, body io.Reader, contentType string) (*http.Response, error) {
	url := c.baseURL + path

	// Create request
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create request")
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if c.username != "" {
		req.SetBasicAuth(c.username, c.password)
	}

	return c.httpClient.Do(req)
}

// SSLCertificateEntry represents an SSL certificate entry from storage API
type SSLCertificateEntry struct {
	File        string `json:"file"`
	StorageName string `json:"storage_name"`
	Description string `json:"description"`
}

// CertificateRef holds both display name and file path for a certificate
type CertificateRef struct {
	// DisplayName is the storage_name or filename for display purposes
	DisplayName string
	// FilePath is the full file path used for API lookups
	FilePath string
}

// ListCertificates returns a list of certificates from HAProxy Data Plane API
func (c *Client) ListCertificates() ([]string, error) {
	refs, err := c.ListCertificateRefs()
	if err != nil {
		return nil, err
	}

	var certNames []string
	for _, ref := range refs {
		certNames = append(certNames, ref.DisplayName)
	}
	return certNames, nil
}

// ListCertificateRefs returns a list of certificate references with both display names and file paths
func (c *Client) ListCertificateRefs() ([]CertificateRef, error) {
	// Use storage API endpoint for listing SSL certificates
	resp, err := c.doRequest("GET", "/v2/services/haproxy/storage/ssl_certificates", nil, "")
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, errors.Errorf("failed to list certificates: status %d, body: %s", resp.StatusCode, string(body))
	}

	var certs []SSLCertificateEntry
	if err := json.NewDecoder(resp.Body).Decode(&certs); err != nil {
		return nil, errors.Wrap(err, "failed to decode certificate list")
	}

	var refs []CertificateRef
	for _, cert := range certs {
		ref := CertificateRef{
			FilePath: cert.File,
		}
		// Prefer storage_name for display, fall back to file path
		if cert.StorageName != "" {
			ref.DisplayName = cert.StorageName
		} else if cert.File != "" {
			ref.DisplayName = cert.File
		}
		if ref.DisplayName != "" || ref.FilePath != "" {
			refs = append(refs, ref)
		}
	}

	return refs, nil
}

// GetCertificateInfo retrieves detailed information about a specific certificate by name
func (c *Client) GetCertificateInfo(certName string) (*CertInfo, error) {
	return c.GetCertificateInfoByPath(certName, certName)
}

// GetCertificateInfoByPath retrieves detailed information about a certificate using its file path
func (c *Client) GetCertificateInfoByPath(filePath, displayName string) (*CertInfo, error) {
	// URL-encode the file path for the API request
	encodedPath := url.PathEscape(filePath)
	path := fmt.Sprintf("/v2/services/haproxy/storage/ssl_certificates/%s", encodedPath)
	resp, err := c.doRequest("GET", path, nil, "")
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		return nil, errors.Errorf("certificate %s not found", displayName)
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, errors.Errorf("failed to get certificate info: status %d, body: %s", resp.StatusCode, string(body))
	}

	// The storage API returns the PEM content directly
	pemData, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read certificate data")
	}

	// Parse the PEM certificate to extract info
	info, err := parsePEMCertificate(pemData, displayName)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse certificate")
	}

	return info, nil
}

// GetCertificateInfoByRef retrieves detailed information using a CertificateRef
func (c *Client) GetCertificateInfoByRef(ref CertificateRef) (*CertInfo, error) {
	// Use DisplayName (storage_name) for API lookup, as the HAProxy Data Plane API
	// storage endpoint expects the storage name, not the full filesystem path
	lookupPath := ref.DisplayName
	if lookupPath == "" {
		lookupPath = ref.FilePath
	}
	return c.GetCertificateInfoByPath(lookupPath, ref.DisplayName)
}

// parsePEMCertificate parses a PEM certificate and extracts certificate info
func parsePEMCertificate(pemData []byte, certName string) (*CertInfo, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse X.509 certificate")
	}

	info := &CertInfo{
		StorageName: certName,
		Subject:     cert.Subject.String(),
		Issuer:      cert.Issuer.String(),
		Serial:      cert.SerialNumber.Text(16),
		NotBefore:   cert.NotBefore,
		NotAfter:    cert.NotAfter,
		SANs:        cert.DNSNames,
	}

	return info, nil
}

// parseDataPlaneAPITime parses time strings from Data Plane API
func parseDataPlaneAPITime(s string) (time.Time, error) {
	// Data Plane API may return time in various formats
	formats := []string{
		time.RFC3339,
		"2006-01-02T15:04:05Z",
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

// UpdateCertificate uploads and commits a certificate update via Data Plane API
func (c *Client) UpdateCertificate(certName, pemData string) error {
	// Create multipart form data
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)

	// Add file part
	part, err := writer.CreateFormFile("file_upload", certName)
	if err != nil {
		return errors.Wrap(err, "failed to create form file")
	}
	if _, err := part.Write([]byte(pemData)); err != nil {
		return errors.Wrap(err, "failed to write certificate data")
	}

	if err := writer.Close(); err != nil {
		return errors.Wrap(err, "failed to close multipart writer")
	}

	// Send PUT request to replace certificate
	path := fmt.Sprintf("/v2/services/haproxy/runtime/certs/%s", certName)
	resp, err := c.doRequest("PUT", path, &buf, writer.FormDataContentType())
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		body, _ := io.ReadAll(resp.Body)
		return errors.Errorf("failed to update certificate %s: status %d, body: %s", certName, resp.StatusCode, string(body))
	}

	c.logger.Debugf("Updated certificate %s", certName)
	return nil
}

// CreateCertificate creates a new certificate entry via Data Plane API
func (c *Client) CreateCertificate(certName, pemData string) error {
	// Create multipart form data
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)

	// Add file part
	part, err := writer.CreateFormFile("file_upload", certName)
	if err != nil {
		return errors.Wrap(err, "failed to create form file")
	}
	if _, err := part.Write([]byte(pemData)); err != nil {
		return errors.Wrap(err, "failed to write certificate data")
	}

	if err := writer.Close(); err != nil {
		return errors.Wrap(err, "failed to close multipart writer")
	}

	// Send POST request to create certificate
	resp, err := c.doRequest("POST", "/v2/services/haproxy/runtime/certs", &buf, writer.FormDataContentType())
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return errors.Errorf("failed to create certificate %s: status %d, body: %s", certName, resp.StatusCode, string(body))
	}

	c.logger.Debugf("Created certificate %s", certName)
	return nil
}

// DeleteCertificate deletes a certificate entry via Data Plane API
func (c *Client) DeleteCertificate(certName string) error {
	path := fmt.Sprintf("/v2/services/haproxy/runtime/certs/%s", certName)
	resp, err := c.doRequest("DELETE", path, nil, "")
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return errors.Errorf("failed to delete certificate %s: status %d, body: %s", certName, resp.StatusCode, string(body))
	}

	c.logger.Debugf("Deleted certificate %s", certName)
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

// logrusLeveledLogger wraps a logrus.Logger to implement retryablehttp.LeveledLogger
type logrusLeveledLogger struct {
	logger *logrus.Logger
}

func (l *logrusLeveledLogger) Error(msg string, keysAndValues ...interface{}) {
	l.logger.WithFields(toLogrusFields(keysAndValues)).Error(msg)
}

func (l *logrusLeveledLogger) Info(msg string, keysAndValues ...interface{}) {
	l.logger.WithFields(toLogrusFields(keysAndValues)).Info(msg)
}

func (l *logrusLeveledLogger) Debug(msg string, keysAndValues ...interface{}) {
	l.logger.WithFields(toLogrusFields(keysAndValues)).Debug(msg)
}

func (l *logrusLeveledLogger) Warn(msg string, keysAndValues ...interface{}) {
	l.logger.WithFields(toLogrusFields(keysAndValues)).Warn(msg)
}

// toLogrusFields converts key-value pairs to logrus.Fields
func toLogrusFields(keysAndValues []any) logrus.Fields {
	fields := logrus.Fields{}
	for i := 0; i+1 < len(keysAndValues); i += 2 {
		key, ok := keysAndValues[i].(string)
		if !ok {
			continue
		}
		fields[key] = keysAndValues[i+1]
	}
	return fields
}
