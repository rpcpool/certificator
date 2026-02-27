package haproxy

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/go-retryablehttp"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// CertInfo holds certificate information.
// Note: HAProxy Data Plane API only returns Filename and StorageName.
// Other fields (NotAfter, Serial) are only populated when parsing PEM data directly.
type CertInfo struct {
	Filename    string    `json:"file"`
	StorageName string    `json:"storage_name"`
	NotAfter    time.Time `json:"-"`
	Serial      string    `json:"serial"`
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
	certs, err := c.listCertificateRefsV2()
	if err != nil {
		return nil, err
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

func (c *Client) listCertificateRefsV2() ([]SSLCertificateEntry, error) {
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

	return certs, nil
}

// UpdateCertificate uploads and commits a certificate update via Data Plane API
func (c *Client) UpdateCertificate(certName, pemData string) error {
	version, err := c.getConfigurationVersion()
	if err != nil {
		return err
	}
	return c.updateCertificateStorageV2(certName, pemData, version)
}

func (c *Client) updateCertificateStorageV2(certName, pemData string, version int) error {
	path := fmt.Sprintf("/v2/services/haproxy/storage/ssl_certificates/%s?version=%d", certName, version)
	resp, err := c.doRequest("PUT", path, strings.NewReader(pemData), "text/plain")
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
	version, err := c.getConfigurationVersion()
	if err != nil {
		return err
	}

	// Create multipart form data
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
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

	path := fmt.Sprintf("/v2/services/haproxy/storage/ssl_certificates?version=%d", version)
	resp, err := c.doRequest("POST", path, &buf, writer.FormDataContentType())
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		body, _ := io.ReadAll(resp.Body)
		return errors.Errorf("failed to create certificate %s: status %d, body: %s", certName, resp.StatusCode, string(body))
	}

	c.logger.Debugf("Created certificate %s", certName)
	return nil
}

// DeleteCertificate deletes a certificate entry via Data Plane API
func (c *Client) DeleteCertificate(certName string) error {
	version, err := c.getConfigurationVersion()
	if err != nil {
		return err
	}

	path := fmt.Sprintf("/v2/services/haproxy/storage/ssl_certificates/%s?version=%d", certName, version)
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

// ListFrontends returns frontend names from HAProxy configuration.
func (c *Client) ListFrontends() ([]string, error) {
	resp, err := c.doRequest("GET", "/v2/services/haproxy/configuration/frontends", nil, "")
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, errors.Errorf("failed to list frontends: status %d, body: %s", resp.StatusCode, string(body))
	}

	data, err := decodeDataArray(resp.Body)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decode frontends list")
	}

	var names []string
	for _, item := range data {
		if name, ok := item["name"].(string); ok && name != "" {
			names = append(names, name)
		}
	}
	return names, nil
}

// ListBinds returns bind objects for the given frontend.
func (c *Client) ListBinds(frontend string) ([]map[string]any, error) {
	path := fmt.Sprintf("/v2/services/haproxy/configuration/binds?frontend=%s", frontend)
	resp, err := c.doRequest("GET", path, nil, "")
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, errors.Errorf("failed to list binds: status %d, body: %s", resp.StatusCode, string(body))
	}

	data, err := decodeDataArray(resp.Body)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decode binds list")
	}

	return data, nil
}

// UpdateBind updates a bind in the HAProxy configuration.
func (c *Client) UpdateBind(frontend, bindName string, bind map[string]any) error {
	version, err := c.getConfigurationVersion()
	if err != nil {
		return err
	}

	bind["name"] = bindName
	payload, err := json.Marshal(bind)
	if err != nil {
		return errors.Wrap(err, "failed to encode bind payload")
	}

	path := fmt.Sprintf("/v2/services/haproxy/configuration/frontends/%s/binds/%s?version=%d", frontend, bindName, version)
	resp, err := c.doRequest("PUT", path, strings.NewReader(string(payload)), "application/json")
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		body, _ := io.ReadAll(resp.Body)
		return errors.Errorf("failed to update bind %s on frontend %s: status %d, body: %s", bindName, frontend, resp.StatusCode, string(body))
	}

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

func (l *logrusLeveledLogger) Error(msg string, keysAndValues ...any) {
	l.logger.WithFields(toLogrusFields(keysAndValues)).Error(msg)
}

func (l *logrusLeveledLogger) Info(msg string, keysAndValues ...any) {
	l.logger.WithFields(toLogrusFields(keysAndValues)).Info(msg)
}

func (l *logrusLeveledLogger) Debug(msg string, keysAndValues ...any) {
	l.logger.WithFields(toLogrusFields(keysAndValues)).Debug(msg)
}

func (l *logrusLeveledLogger) Warn(msg string, keysAndValues ...any) {
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

func (c *Client) getConfigurationVersion() (int, error) {
	resp, err := c.doRequest("GET", "/v2/services/haproxy/configuration/version", nil, "")
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return 0, errors.Errorf("failed to get configuration version: status %d, body: %s", resp.StatusCode, string(body))
	}

	var versionValue any
	if err := json.NewDecoder(resp.Body).Decode(&versionValue); err != nil {
		return 0, errors.Wrap(err, "failed to decode configuration version")
	}

	switch v := versionValue.(type) {
	case float64:
		return int(v), nil
	case string:
		return strconv.Atoi(v)
	case map[string]any:
		if raw, ok := v["_version"]; ok {
			return parseVersionValue(raw)
		}
		if raw, ok := v["version"]; ok {
			return parseVersionValue(raw)
		}
	}

	return 0, errors.New("unsupported configuration version response")
}

func parseVersionValue(value any) (int, error) {
	switch v := value.(type) {
	case float64:
		return int(v), nil
	case string:
		return strconv.Atoi(v)
	default:
		return 0, errors.New("unsupported configuration version value")
	}
}

func decodeDataArray(r io.Reader) ([]map[string]any, error) {
	var envelope map[string]any
	if err := json.NewDecoder(r).Decode(&envelope); err != nil {
		return nil, err
	}

	rawData, ok := envelope["data"]
	if !ok {
		return nil, errors.New("response missing data field")
	}

	items, ok := rawData.([]any)
	if !ok {
		return nil, errors.New("data field is not a list")
	}

	out := make([]map[string]any, 0, len(items))
	for _, item := range items {
		if obj, ok := item.(map[string]any); ok {
			out = append(out, obj)
		}
	}

	return out, nil
}
