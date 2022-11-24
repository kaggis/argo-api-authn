package config

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"github.com/ARGOeu/argo-api-authn/utils"
	log "github.com/sirupsen/logrus"
	lSyslog "github.com/sirupsen/logrus/hooks/syslog"
	"io/ioutil"
	"log/syslog"
	"reflect"
)

const (
	DefaultServerReadTimeout       = 5
	DefaultServerHeaderReadTimeout = 5
	DefaultServerWriteTimeout      = 15
	DefaultServerIdleTimeout       = 60
)

type Config struct {
	ServicePort                 int               `json:"service_port" required:"true"`
	MongoHost                   string            `json:"mongo_host" required:"true"`
	MongoDB                     string            `json:"mongo_db" required:"true"`
	CertificateAuthorities      string            `json:"certificate_authorities" required:"true"`
	Certificate                 string            `json:"certificate" required:"true"`
	CertificateKey              string            `json:"certificate_key" required:"true"`
	ServiceToken                string            `json:"service_token" required:"true"`
	SupportedAuthTypes          []string          `json:"supported_auth_types" required:"true"`
	SupportedAuthMethods        []string          `json:"supported_auth_methods" required:"true"`
	SupportedServiceTypes       []string          `json:"supported_service_types" required:"true"`
	VerifySSL                   bool              `json:"verify_ssl"`
	TrustUnknownCAs             bool              `json:"trust_unknown_cas"`
	VerifyCertificate           bool              `json:"verify_certificate"`
	ServiceTypesPaths           map[string]string `json:"service_types_paths" required:"true"`
	ServiceTypesRetrievalFields map[string]string `json:"service_types_retrieval_fields" required:"true"`
	SyslogEnabled               bool              `json:"syslog_enabled"`
	ClientCertHostVerification  bool              `json:"client_cert_host_verification"`
	ServerReadTimeout           int               `json:"server_read_timeout"`
	ServerHeaderReadTimeout     int               `json:"server_header_read_timeout"`
	ServerWriteTimeout          int               `json:"server_write_timeout"`
	ServerIdleTimeout           int               `json:"server_idle_timeout"`
}

func WithDefaults() *Config {
	return &Config{
		ServerReadTimeout:       DefaultServerReadTimeout,
		ServerHeaderReadTimeout: DefaultServerHeaderReadTimeout,
		ServerWriteTimeout:      DefaultServerWriteTimeout,
		ServerIdleTimeout:       DefaultServerIdleTimeout,
	}

}

// ConfigSetUp unmarshalls a json file specified by the input parameter into the config object
func (cfg *Config) ConfigSetUp(path string) error {

	var data []byte
	var err error

	if data, err = ioutil.ReadFile(path); err != nil {
		return err
	}

	if err = json.Unmarshal(data, &cfg); err != nil {
		return errors.New("Something went wrong while marshaling the json data. Error: " + err.Error())
	}

	if cfg.SyslogEnabled {
		hook, err := lSyslog.NewSyslogHook("", "", syslog.LOG_INFO, "")
		if err == nil {
			log.AddHook(hook)
		}
	}

	if err = utils.ValidateRequired(*cfg); err != nil {
		return utils.StructGenericEmptyRequiredField("config", err.Error())
	}

	rvc := reflect.ValueOf(*cfg)

	for i := 0; i < rvc.NumField(); i++ {

		fl := rvc.Type().Field(i)

		log.WithFields(
			log.Fields{
				"type": "service_log",
			},
		).Infof("Parameter loaded %v - %v", fl.Name, rvc.Field(i).Interface())
	}
	return nil
}

// ClintAuthPolicy determines, based on the given configuration what client authentication policy should the server follow
func (cfg *Config) ClientAuthPolicy() tls.ClientAuthType {

	var policy = tls.VerifyClientCertIfGiven

	if cfg.TrustUnknownCAs {
		policy = tls.RequestClientCert
	}

	return policy

}
