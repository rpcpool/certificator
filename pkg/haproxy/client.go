package haproxy

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"mime/multipart"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/vinted/certificator/pkg/certmetrics"
)

// Default retry configuration
const (
	DefaultMaxRetries     = 3
	DefaultRetryBaseDelay = 1 * time.Second
	DefaultRetryMaxDelay  = 30 * time.Second
)

// RetryConfig holds retry configuration for HAProxy connections
type RetryConfig struct {
	MaxRetries int           // Maximum number of retry attempts (0 = no retries)
	BaseDelay  time.Duration // Initial delay between retries
	MaxDelay   time.Duration // Maximum delay between retries (for exponential backoff)
}

// DefaultRetryConfig returns the default retry configuration
func DefaultRetryConfig() RetryConfig {
	return RetryConfig{
		MaxRetries: DefaultMaxRetries,
		BaseDelay:  DefaultRetryBaseDelay,
		MaxDelay:   DefaultRetryMaxDelay,
	}
}

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
	baseURL     string
	username    string
	password    string
	httpClient  *http.Client
	logger      *logrus.Logger
	retryConfig RetryConfig
	timeout     time.Duration
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

	return &Client{
		baseURL:  cfg.BaseURL,
		username: cfg.Username,
		password: cfg.Password,
		httpClient: &http.Client{
			Timeout:   timeout,
			Transport: transport,
		},
		logger:      logger,
		retryConfig: DefaultRetryConfig(),
		timeout:     timeout,
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

// SetRetryConfig sets the retry configuration for this client
func (c *Client) SetRetryConfig(config RetryConfig) {
	c.retryConfig = config
}

// GetRetryConfig returns the current retry configuration
func (c *Client) GetRetryConfig() RetryConfig {
	return c.retryConfig
}

// calculateBackoff calculates the delay for the given retry attempt using exponential backoff
func (c *Client) calculateBackoff(attempt int) time.Duration {
	if attempt <= 0 {
		return c.retryConfig.BaseDelay
	}

	// Exponential backoff: baseDelay * 2^attempt
	delay := float64(c.retryConfig.BaseDelay) * math.Pow(2, float64(attempt))

	// Cap at max delay
	if delay > float64(c.retryConfig.MaxDelay) {
		delay = float64(c.retryConfig.MaxDelay)
	}

	return time.Duration(delay)
}

// doRequest performs an HTTP request with retry logic
func (c *Client) doRequest(method, path string, body io.Reader, contentType string) (*http.Response, error) {
	var lastErr error
	url := c.baseURL + path

	for attempt := 0; attempt <= c.retryConfig.MaxRetries; attempt++ {
		if attempt > 0 {
			certmetrics.HAProxyConnectionRetries.WithLabelValues(c.baseURL).Inc()
			delay := c.calculateBackoff(attempt - 1)
			c.logger.Debugf("Retry %d/%d for %s after %v", attempt, c.retryConfig.MaxRetries, c.baseURL, delay)
			time.Sleep(delay)
		}

		// Need to recreate body for retries if it was consumed
		var reqBody io.Reader
		if body != nil {
			// Read body into buffer for potential retries
			if attempt == 0 {
				reqBody = body
			} else {
				// Body was already consumed, skip retry with body
				reqBody = nil
			}
		}

		// Create request
		req, err := http.NewRequest(method, url, reqBody)
		if err != nil {
			return nil, errors.Wrap(err, "failed to create request")
		}

		// Set headers
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
		if c.username != "" {
			req.SetBasicAuth(c.username, c.password)
		}

		// Execute request
		start := time.Now()
		resp, err := c.httpClient.Do(req)
		duration := time.Since(start)

		// Record metrics
		cmdName := method + " " + extractPathPrefix(path)
		certmetrics.HAProxyCommandDuration.WithLabelValues(c.baseURL, cmdName).Observe(duration.Seconds())

		if err == nil {
			certmetrics.HAProxyConnectionsTotal.WithLabelValues(c.baseURL, "success").Inc()
			certmetrics.HAProxyEndpointsUp.WithLabelValues(c.baseURL).Set(1)
			if attempt > 0 {
				c.logger.Infof("Successfully connected to %s after %d retries", c.baseURL, attempt)
			}
			return resp, nil
		}

		lastErr = err
		c.logger.Debugf("Request attempt %d failed for %s: %v", attempt+1, c.baseURL, err)
	}

	certmetrics.HAProxyConnectionsTotal.WithLabelValues(c.baseURL, "failure").Inc()
	certmetrics.HAProxyEndpointsUp.WithLabelValues(c.baseURL).Set(0)
	return nil, errors.Wrapf(lastErr, "failed to connect to HAProxy Data Plane API at %s after %d attempts", c.baseURL, c.retryConfig.MaxRetries+1)
}

// doRequestWithBodyBuffer performs an HTTP request with retry logic, buffering body for retries
func (c *Client) doRequestWithBodyBuffer(method, path string, bodyData []byte, contentType string) (*http.Response, error) {
	var lastErr error
	url := c.baseURL + path

	for attempt := 0; attempt <= c.retryConfig.MaxRetries; attempt++ {
		if attempt > 0 {
			certmetrics.HAProxyConnectionRetries.WithLabelValues(c.baseURL).Inc()
			delay := c.calculateBackoff(attempt - 1)
			c.logger.Debugf("Retry %d/%d for %s after %v", attempt, c.retryConfig.MaxRetries, c.baseURL, delay)
			time.Sleep(delay)
		}

		// Create request with fresh body reader
		var body io.Reader
		if bodyData != nil {
			body = bytes.NewReader(bodyData)
		}

		req, err := http.NewRequest(method, url, body)
		if err != nil {
			return nil, errors.Wrap(err, "failed to create request")
		}

		// Set headers
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
		if c.username != "" {
			req.SetBasicAuth(c.username, c.password)
		}

		// Execute request
		start := time.Now()
		resp, err := c.httpClient.Do(req)
		duration := time.Since(start)

		// Record metrics
		cmdName := method + " " + extractPathPrefix(path)
		certmetrics.HAProxyCommandDuration.WithLabelValues(c.baseURL, cmdName).Observe(duration.Seconds())

		if err == nil {
			certmetrics.HAProxyConnectionsTotal.WithLabelValues(c.baseURL, "success").Inc()
			certmetrics.HAProxyEndpointsUp.WithLabelValues(c.baseURL).Set(1)
			if attempt > 0 {
				c.logger.Infof("Successfully connected to %s after %d retries", c.baseURL, attempt)
			}
			return resp, nil
		}

		lastErr = err
		c.logger.Debugf("Request attempt %d failed for %s: %v", attempt+1, c.baseURL, err)
	}

	certmetrics.HAProxyConnectionsTotal.WithLabelValues(c.baseURL, "failure").Inc()
	certmetrics.HAProxyEndpointsUp.WithLabelValues(c.baseURL).Set(0)
	return nil, errors.Wrapf(lastErr, "failed to connect to HAProxy Data Plane API at %s after %d attempts", c.baseURL, c.retryConfig.MaxRetries+1)
}

// extractPathPrefix extracts a meaningful prefix from the path for metrics labeling
func extractPathPrefix(path string) string {
	// Extract first two path segments for labeling
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) >= 2 {
		return "/" + parts[0] + "/" + parts[1]
	}
	if len(parts) == 1 {
		return "/" + parts[0]
	}
	return "/"
}

// ListCertificates returns a list of certificates from HAProxy Data Plane API
func (c *Client) ListCertificates() ([]string, error) {
	resp, err := c.doRequest("GET", "/v3/services/haproxy/runtime/certs", nil, "")
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, errors.Errorf("failed to list certificates: status %d, body: %s", resp.StatusCode, string(body))
	}

	var certs []CertInfo
	if err := json.NewDecoder(resp.Body).Decode(&certs); err != nil {
		return nil, errors.Wrap(err, "failed to decode certificate list")
	}

	var certNames []string
	for _, cert := range certs {
		if cert.Filename != "" {
			certNames = append(certNames, cert.Filename)
		} else if cert.StorageName != "" {
			certNames = append(certNames, cert.StorageName)
		}
	}

	return certNames, nil
}

// GetCertificateInfo retrieves detailed information about a specific certificate
func (c *Client) GetCertificateInfo(certName string) (*CertInfo, error) {
	path := fmt.Sprintf("/v3/services/haproxy/runtime/certs/%s", certName)
	resp, err := c.doRequest("GET", path, nil, "")
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		return nil, errors.Errorf("certificate %s not found", certName)
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, errors.Errorf("failed to get certificate info: status %d, body: %s", resp.StatusCode, string(body))
	}

	var info CertInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, errors.Wrap(err, "failed to decode certificate info")
	}

	// Parse time strings
	if info.NotBeforeStr != "" {
		if t, err := parseDataPlaneAPITime(info.NotBeforeStr); err == nil {
			info.NotBefore = t
		}
	}
	if info.NotAfterStr != "" {
		if t, err := parseDataPlaneAPITime(info.NotAfterStr); err == nil {
			info.NotAfter = t
		}
	}

	return &info, nil
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
	path := fmt.Sprintf("/v3/services/haproxy/runtime/certs/%s", certName)
	resp, err := c.doRequestWithBodyBuffer("PUT", path, buf.Bytes(), writer.FormDataContentType())
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
	resp, err := c.doRequestWithBodyBuffer("POST", "/v3/services/haproxy/runtime/certs", buf.Bytes(), writer.FormDataContentType())
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
	path := fmt.Sprintf("/v3/services/haproxy/runtime/certs/%s", certName)
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
