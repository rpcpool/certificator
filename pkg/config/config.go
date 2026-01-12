package config

import (
	"os"
	"strings"
	"time"

	"github.com/kelseyhightower/envconfig"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// Acme contains acme related configuration parameters
type Acme struct {
	AccountEmail              string `envconfig:"ACME_ACCOUNT_EMAIL" default:""`
	DNSChallengeProvider      string `envconfig:"ACME_DNS_CHALLENGE_PROVIDER" default:""`
	DNSPropagationRequirement bool   `envconfig:"ACME_DNS_PROPAGATION_REQUIREMENT" default:"true"`
	ReregisterAccount         bool   `envconfig:"ACME_REREGISTER_ACCOUNT" default:"false"`
	ServerURL                 string `envconfig:"ACME_SERVER_URL" default:"https://acme-staging-v02.api.letsencrypt.org/directory"`
	EABKid                    string `envconfig:"EAB_KID" default:""`
	EABHmacKey                string `envconfig:"EAB_HMAC_KEY" default:""`
}

// Vault contains vault related configuration parameters
type Vault struct {
	ApproleRoleID   string `envconfig:"VAULT_APPROLE_ROLE_ID"`
	ApproleSecretID string `envconfig:"NOMAD_TOKEN"`
	KVStoragePath   string `envconfig:"VAULT_KV_STORAGE_PATH" default:"secret/data/certificator/"`
}

type Log struct {
	Format string         `envconfig:"LOG_FORMAT" default:"JSON"`
	Level  string         `envconfig:"LOG_LEVEL" default:"INFO"`
	Logger *logrus.Logger `envconfig:"-"`
}

type Metrics struct {
	ListenAddress string `envconfig:"METRICS_LISTEN_ADDRESS"`
	PushAddress   string `envconfig:"METRICS_PUSH_ADDRESS"`
}

// Config contains all configuration parameters
type Config struct {
	Hostname        string
	Acme            Acme
	Vault           Vault
	Log             Log
	Metrics         Metrics
	Certificatee    Certificatee
	DNSAddress      string   `envconfig:"DNS_ADDRESS" default:"127.0.0.1:53"`
	Environment     string   `envconfig:"ENVIRONMENT" default:"prod"`
	RenewBeforeDays int      `envconfig:"CERTIFICATOR_RENEW_BEFORE_DAYS" default:"30"`
	Domains         []string `envconfig:"CERTIFICATOR_DOMAINS" default:""`
}

// Configuration values specific to the certificatee tool
type Certificatee struct {
	CertificatePath      string        `envconfig:"CERTIFICATEE_CERTIFICATE_PATH" default:""`
	CertificateExtension string        `envconfig:"CERTIFICATEE_CERTIFICATE_EXTENSION" default:""`
	UpdateInterval       time.Duration `envconfig:"CERTIFICATEE_UPDATE_INTERVAL" default:"24h"`
}

// LoadConfig loads configuration options to  variable
func LoadConfig() (Config, error) {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	cfg := Config{
		Hostname: hostname,
		Log: Log{
			Logger: logrus.New(),
		},
	}

	if err := envconfig.Process("", &cfg); err != nil {
		return cfg, errors.Wrapf(err, "failed getting config from env")
	}

	switch cfg.Log.Format {
	case "JSON":
		cfg.Log.Logger.SetFormatter(&logrus.JSONFormatter{})
	default: // "LOGFMT" or any other value
		cfg.Log.Logger.SetFormatter(&logrus.TextFormatter{})
	}

	logLevel, err := logrus.ParseLevel(strings.ToLower(cfg.Log.Level))
	if err != nil {
		cfg.Log.Logger.Errorf("Invalid log level: %s, using INFO", cfg.Log.Level)
		logLevel = logrus.InfoLevel
	}
	cfg.Log.Logger.SetLevel(logLevel)

	return cfg, nil
}
