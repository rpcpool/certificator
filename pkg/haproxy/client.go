package haproxy

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
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

// UnexpectedStatusError is returned when the Data Plane API responds with an
// HTTP status that is not valid for the requested operation.
type UnexpectedStatusError struct {
	Operation  string
	StatusCode int
	Body       string
}

func (e *UnexpectedStatusError) Error() string {
	return fmt.Sprintf("%s: status %d, body: %s", e.Operation, e.StatusCode, e.Body)
}

// IsHTTPStatus reports whether err wraps an UnexpectedStatusError with the
// given status code.
func IsHTTPStatus(err error, statusCode int) bool {
	var statusErr *UnexpectedStatusError
	return errors.As(err, &statusErr) && statusErr.StatusCode == statusCode
}

func unexpectedStatusError(operation string, statusCode int, body []byte) error {
	return &UnexpectedStatusError{
		Operation:  operation,
		StatusCode: statusCode,
		Body:       string(body),
	}
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

func parseAPITime(value string) (time.Time, error) {
	if value == "" {
		return time.Time{}, nil
	}

	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err == nil {
		return parsed, nil
	}

	return time.Parse(time.RFC3339, value)
}

// SSLCertificateEntry represents an SSL certificate entry from the Data Plane API.
type SSLCertificateEntry struct {
	File        string `json:"file"`
	StorageName string `json:"storage_name"`
	Description string `json:"description"`
}

type sslCertificateDetailResponse struct {
	File                    string `json:"file"`
	StorageName             string `json:"storage_name"`
	Description             string `json:"description"`
	Domains                 string `json:"domains"`
	Issuers                 string `json:"issuers"`
	NotAfter                string `json:"not_after"`
	NotBefore               string `json:"not_before"`
	Serial                  string `json:"serial"`
	SubjectAlternativeNames string `json:"subject_alternative_names"`
}

// CertificateDetail describes the current HAProxy certificate state reported by
// the Data Plane API.
type CertificateDetail struct {
	File                    string
	StorageName             string
	Description             string
	Domains                 string
	Issuers                 string
	NotAfter                time.Time
	NotBefore               time.Time
	Serial                  string
	SubjectAlternativeNames string
}

// CertificateRef holds both display and runtime API names for a certificate.
type CertificateRef struct {
	// DisplayName is the filename used for logs and Vault domain extraction.
	DisplayName string
	// APIName is the DPAPI runtime ssl_certs name used for detail and update calls.
	APIName string
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

// ListCertificateRefs returns the certificates currently loaded by HAProxy.
func (c *Client) ListCertificateRefs() ([]CertificateRef, error) {
	resp, err := c.doRequest("GET", "/v3/services/haproxy/runtime/ssl_certs", nil, "")
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, unexpectedStatusError("failed to list live certificates", resp.StatusCode, body)
	}

	var certs []SSLCertificateEntry
	if err := json.NewDecoder(resp.Body).Decode(&certs); err != nil {
		return nil, errors.Wrap(err, "failed to decode certificate list")
	}

	var refs []CertificateRef
	for _, cert := range certs {
		apiName := cert.StorageName
		if apiName == "" {
			apiName = cert.File
		}

		displayName := cert.Description
		if displayName == "" {
			displayName = apiName
		}

		if apiName != "" && displayName != "" {
			refs = append(refs, CertificateRef{
				DisplayName: displayName,
				APIName:     apiName,
			})
		}
	}

	return refs, nil
}

// GetCertificateDetail returns live HAProxy certificate metadata from the
// Data Plane API v3 runtime endpoint.
func (c *Client) GetCertificateDetail(certName string) (*CertificateDetail, error) {
	path := fmt.Sprintf("/v3/services/haproxy/runtime/ssl_certs/%s", url.PathEscape(certName))
	resp, err := c.doRequest("GET", path, nil, "")
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, errors.Errorf("failed to get certificate %s: status %d, body: %s", certName, resp.StatusCode, string(body))
	}

	var raw sslCertificateDetailResponse
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, errors.Wrap(err, "failed to decode certificate detail")
	}

	notAfter, err := parseAPITime(raw.NotAfter)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to parse not_after for certificate %s", certName)
	}

	notBefore, err := parseAPITime(raw.NotBefore)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to parse not_before for certificate %s", certName)
	}

	return &CertificateDetail{
		File:                    raw.File,
		StorageName:             raw.StorageName,
		Description:             raw.Description,
		Domains:                 raw.Domains,
		Issuers:                 raw.Issuers,
		NotAfter:                notAfter,
		NotBefore:               notBefore,
		Serial:                  raw.Serial,
		SubjectAlternativeNames: raw.SubjectAlternativeNames,
	}, nil
}

// UpdateCertificate uploads a replacement certificate to the live HAProxy
// runtime via Data Plane API v3. Runtime updates take effect immediately but
// are not persisted across a full HAProxy restart.
func (c *Client) UpdateCertificate(certName, pemData string) error {
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

	path := fmt.Sprintf("/v3/services/haproxy/runtime/ssl_certs/%s", url.PathEscape(certName))
	resp, err := c.doRequest("PUT", path, &buf, writer.FormDataContentType())
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		body, _ := io.ReadAll(resp.Body)
		return unexpectedStatusError(fmt.Sprintf("failed to update runtime certificate %s", certName), resp.StatusCode, body)
	}

	c.logger.Debugf("Updated runtime certificate %s", certName)
	return nil
}

// UpdateStorageCertificate replaces a certificate on disk without asking
// Data Plane API to reload HAProxy. Certificatee updates runtime separately
// after this write so the new certificate is both durable and active.
func (c *Client) UpdateStorageCertificate(certName, pemData string) error {
	path := fmt.Sprintf("/v3/services/haproxy/storage/ssl_certificates/%s?skip_reload=true", url.PathEscape(certName))
	resp, err := c.doRequest("PUT", path, strings.NewReader(pemData), "text/plain")
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		body, _ := io.ReadAll(resp.Body)
		return unexpectedStatusError(fmt.Sprintf("failed to update storage certificate %s", certName), resp.StatusCode, body)
	}

	c.logger.Debugf("Updated storage certificate %s", certName)
	return nil
}

// CreateCertificate creates a new certificate entry on disk without asking
// Data Plane API to reload HAProxy.
func (c *Client) CreateCertificate(certName, pemData string) error {
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

	resp, err := c.doRequest("POST", "/v3/services/haproxy/storage/ssl_certificates?skip_reload=true", &buf, writer.FormDataContentType())
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		body, _ := io.ReadAll(resp.Body)
		return unexpectedStatusError(fmt.Sprintf("failed to create storage certificate %s", certName), resp.StatusCode, body)
	}

	c.logger.Debugf("Created storage certificate %s", certName)
	return nil
}

// EnsureStorageCertificate writes a certificate to disk, creating it if it does
// not already exist. The write always uses skip_reload=true.
func (c *Client) EnsureStorageCertificate(certName, pemData string) error {
	if err := c.UpdateStorageCertificate(certName, pemData); err != nil {
		if !IsHTTPStatus(err, http.StatusNotFound) {
			return err
		}

		if err := c.CreateCertificate(certName, pemData); err != nil {
			if IsHTTPStatus(err, http.StatusConflict) {
				return c.UpdateStorageCertificate(certName, pemData)
			}
			return err
		}
	}

	return nil
}

// DeleteCertificate removes a certificate file from HAProxy storage without
// asking Data Plane API to reload HAProxy. The Data Plane API does not accept
// a version parameter for this endpoint, unlike the configuration-changing
// storage write endpoints.
func (c *Client) DeleteCertificate(certName string) error {
	path := fmt.Sprintf("/v3/services/haproxy/storage/ssl_certificates/%s?skip_reload=true", url.PathEscape(certName))
	resp, err := c.doRequest("DELETE", path, nil, "")
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusAccepted {
		body, _ := io.ReadAll(resp.Body)
		return unexpectedStatusError(fmt.Sprintf("failed to delete certificate %s", certName), resp.StatusCode, body)
	}

	c.logger.Debugf("Deleted storage certificate %s", certName)
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

// NormalizeDomainForVault converts a sanitized cert filename domain back to the
// Vault lookup key. HAProxy stores wildcard certs as "_.domain" on disk, but
// certificator stores them in Vault as "*.domain".
func NormalizeDomainForVault(domain string) string {
	if strings.HasPrefix(domain, "_.") {
		return "*." + domain[2:]
	}
	return domain
}

func StorageCertificateName(certPath string) string {
	parts := strings.Split(certPath, "/")
	return parts[len(parts)-1]
}

// IsExpiring checks if a certificate is expiring within the given number of days
func IsExpiring(certInfo *CertInfo, renewBeforeDays int) bool {
	if certInfo == nil {
		return true
	}

	threshold := time.Now().AddDate(0, 0, renewBeforeDays)
	return certInfo.NotAfter.Before(threshold)
}

// NormalizeSerial normalizes a certificate serial number for comparison.
// Removes non-hex characters, converts to uppercase, and strips insignificant
// leading zeroes.
func NormalizeSerial(serial string) string {
	var b strings.Builder
	b.Grow(len(serial))

	for _, ch := range serial {
		switch {
		case ch >= '0' && ch <= '9':
			b.WriteRune(ch)
		case ch >= 'a' && ch <= 'f':
			b.WriteRune(ch - ('a' - 'A'))
		case ch >= 'A' && ch <= 'F':
			b.WriteRune(ch)
		}
	}

	normalized := b.String()
	if normalized == "" {
		return ""
	}

	trimmed := strings.TrimLeft(normalized, "0")
	if trimmed == "" {
		return "0"
	}

	return trimmed
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
