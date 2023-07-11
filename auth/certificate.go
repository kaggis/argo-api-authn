package auth

import (
	"context"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"

	"net"
	"strings"
	"time"

	"github.com/ARGOeu/argo-api-authn/utils"
	log "github.com/sirupsen/logrus"
)

const (
	DomainComponentRDN = "DC"
	EmailAddressRDN    = "E"
)

var NonStandardAttributeNames = map[string]string{
	"0.9.2342.19200300.100.1.25": DomainComponentRDN,
	"1.2.840.113549.1.9.1":       EmailAddressRDN,
}

// IPSANExtensionID is a constant representing the Extension ID for Subject Alternative Name
var IPSANExtensionID = asn1.ObjectIdentifier{2, 5, 29, 17}

func HasIPSANs(cert *x509.Certificate) bool {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(IPSANExtensionID) {
			return true
		}
	}
	return false
}

// LoadCAs reads the root certificates from a directory within the filesystem, and creates the trusted root CA chain
func LoadCAs(dir string) (roots *x509.CertPool) {

	log.WithFields(
		log.Fields{
			"type": "service_log",
		},
	).Info("Building the root CA chain . . .")
	pattern := "*.pem"
	roots = x509.NewCertPool()
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			log.WithFields(
				log.Fields{
					"type":    "service_log",
					"details": err.Error(),
					"path":    dir,
				},
			).Error("Certificate system path access failure")
			return err
		}
		if ok, _ := filepath.Match(pattern, info.Name()); ok {
			bytes, _ := ioutil.ReadFile(filepath.Join(dir, info.Name()))
			if ok = roots.AppendCertsFromPEM(bytes); !ok {
				return errors.New("Something went wrong while parsing certificate: " + filepath.Join(dir, info.Name()))
			}
		}
		return nil
	})

	if err != nil {
		log.WithFields(
			log.Fields{
				"type":    "service_log",
				"details": err.Error(),
				"path":    dir,
			},
		).Error("Error walking certificate system path")
	} else {
		log.WithFields(
			log.Fields{"type": "service_log"},
		).Info("All certificates parsed successfully!")
	}

	return

}

// ExtractEnhancedRDNSequenceToString extracts a certificate's RDNs to a string using what's provided in the standard library
// and then adding extra attribute names that we have defined
func ExtractEnhancedRDNSequenceToString(cert *x509.Certificate) string {

	var sb strings.Builder

	// create a map that will hold the values of the additional RDNs that we have defined
	// make sure that the initialized keys match the values of the NonStandardAttributeNames map defined in this package
	extraRDNS := map[string][]string{}
	extraRDNS[DomainComponentRDN] = []string{}
	extraRDNS[EmailAddressRDN] = []string{}

	// loop through the attribute names of the cert
	// if the type matches any of the predefined asn1.ObjectIdentifiers then append its value to the respective rdn
	for i := 0; i < len(cert.Subject.Names); i++ {
		atv := cert.Subject.Names[i]
		if value, ok := NonStandardAttributeNames[atv.Type.String()]; ok {
			extraRDNS[value] = append(extraRDNS[value], atv.Value.(string))
		}

	}

	// check if the Email RDN was present
	// EMAIL RDN is more specific than CN so it should be at start of the DN string
	if len(extraRDNS[EmailAddressRDN]) > 0 {
		sb.WriteString(FormatRdnToString(EmailAddressRDN, extraRDNS[EmailAddressRDN]))
		sb.WriteString(",")
	}

	sb.WriteString(cert.Subject.ToRDNSequence().String())

	// check the extra RDNs if the have any registered values
	// DC RDN is the most generic one so it belongs at the end of the DN string
	if len(extraRDNS[DomainComponentRDN]) > 0 {
		sb.WriteString(",")
		sb.WriteString(FormatRdnToString("DC", extraRDNS[DomainComponentRDN]))
	}

	return sb.String()

}

// FormatRdnToString transforms the values of a given RDN to a printable string
// e.g. rdn=DC, rdnValues=[argo, grnet, gr ], ths should be transformed to DC=argo+DC=grnet+DC=gr
func FormatRdnToString(rdn string, rdnValues []string) string {

	var sb strings.Builder

	// operator is a string literal that stands between the values of the given RDN
	var operator string

	// loop through the values and create the printable string
	for _, rdnValue := range rdnValues {

		// if the string is empty, we should use no operator since there are no values present in the string
		if sb.String() != "" {
			operator = "+"
		}

		sb.WriteString(operator)
		sb.WriteString(rdn)
		sb.WriteString("=")
		sb.WriteString(rdnValue)
	}

	return sb.String()
}

// ValidateClientCertificate performs a number of different checks to ensure the provided certificate is valid
func ValidateClientCertificate(ctx context.Context, cert *x509.Certificate, clientIP string, clientCertHostVerification bool) error {

	var err error
	var hosts []string
	var ip string

	log.WithFields(
		log.Fields{
			"trace_id": ctx.Value("trace_id"),
			"type":     "service_log",
			"hosts":    hosts,
			"ip":       clientIP,
		},
	).Info("Validating Client Certificate")

	if clientCertHostVerification {

		if ip, _, err = net.SplitHostPort(clientIP); err != nil {
			err := &utils.APIError{Code: 403, Message: err.Error(), Status: "ACCESS_FORBIDDEN"}
			return err
		}

		if hosts, err = net.LookupAddr(ip); err != nil {
			err = &utils.APIError{Message: err.Error(), Code: 400, Status: "BAD REQUEST"}
			return err
		}

		// loop through hosts and check if any of them matches with the one specified in the certificate
		var tmpErr error
		for _, h := range hosts {
			// if there is an error, hold a temporary error and move to next host
			if err = cert.VerifyHostname(h); err != nil {
				tmpErr = &utils.APIError{Code: 403, Message: err.Error(), Status: "ACCESS_FORBIDDEN"}
				// if there is no error, clear the temporary error and break out of the check loop,
				// if we don't break the loop, if there is another host declared, it will declare a temporary error
			} else {
				tmpErr = nil
				break
			}
		}

		if tmpErr != nil {
			return tmpErr
		}
	}

	// check if the certificate has expired
	if err = CertHasExpired(cert); err != nil {
		return err
	}

	// check if the certificate is revoked
	if err = CRLCheckRevokedCert(ctx, cert); err != nil {
		return err
	}

	return err
}

func CertHasExpired(cert *x509.Certificate) error {

	var err error

	if time.Now().After(cert.NotAfter) {
		err := &utils.APIError{Code: 403, Message: "Your certificate has expired", Status: "ACCESS_FORBIDDEN"}
		return err
	}

	if time.Now().Before(cert.NotBefore) {
		err := &utils.APIError{Code: 403, Message: "Your certificate is not active yet", Status: "ACCESS_FORBIDDEN"}
		return err
	}

	return err
}
