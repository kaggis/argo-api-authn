package auth

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	LOGGER "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/suite"
	"io/ioutil"
	"testing"
)

type RevokeTestSuite struct {
	suite.Suite
}

func ParseCert(pemData string) *x509.Certificate {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		panic("Invalid PEM data.")
	} else if block.Type != "CERTIFICATE" {
		panic("Invalid PEM type.")
	}

	cert, err := x509.ParseCertificate([]byte(block.Bytes))
	if err != nil {
		panic(err.Error())
	}
	return cert
}

// 2014/05/22 14:18:31 Serial number match: intermediate is revoked.
//	2014/05/22 14:18:31 certificate is revoked via CRL
// 2014/05/22 14:18:31 Revoked certificate: misc/intermediate_ca/MobileArmorEnterpriseCA.crt
var revokedCert = `-----BEGIN CERTIFICATE-----
MIIEEzCCAvugAwIBAgILBAAAAAABGMGjftYwDQYJKoZIhvcNAQEFBQAwcTEoMCYG
A1UEAxMfR2xvYmFsU2lnbiBSb290U2lnbiBQYXJ0bmVycyBDQTEdMBsGA1UECxMU
Um9vdFNpZ24gUGFydG5lcnMgQ0ExGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2Ex
CzAJBgNVBAYTAkJFMB4XDTA4MDMxODEyMDAwMFoXDTE4MDMxODEyMDAwMFowJTEj
MCEGA1UEAxMaTW9iaWxlIEFybW9yIEVudGVycHJpc2UgQ0EwggEiMA0GCSqGSIb3
DQEBAQUAA4IBDwAwggEKAoIBAQCaEjeDR73jSZVlacRn5bc5VIPdyouHvGIBUxyS
C6483HgoDlWrWlkEndUYFjRPiQqJFthdJxfglykXD+btHixMIYbz/6eb7hRTdT9w
HKsfH+wTBIdb5AZiNjkg3QcCET5HfanJhpREjZWP513jM/GSrG3VwD6X5yttCIH1
NFTDAr7aqpW/UPw4gcPfkwS92HPdIkb2DYnsqRrnKyNValVItkxJiotQ1HOO3YfX
ivGrHIbJdWYg0rZnkPOgYF0d+aIA4ZfwvdW48+r/cxvLevieuKj5CTBZZ8XrFt8r
JTZhZljbZvnvq/t6ZIzlwOj082f+lTssr1fJ3JsIPnG2lmgTAgMBAAGjgfcwgfQw
DgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQEwHQYDVR0OBBYEFIZw
ns4uzXdLX6xDRXUzFgZxWM7oME0GA1UdIARGMEQwQgYJKwYBBAGgMgE8MDUwMwYI
KwYBBQUHAgIwJxolaHR0cDovL3d3dy5nbG9iYWxzaWduLmNvbS9yZXBvc2l0b3J5
LzA/BgNVHR8EODA2MDSgMqAwhi5odHRwOi8vY3JsLmdsb2JhbHNpZ24ubmV0L1Jv
b3RTaWduUGFydG5lcnMuY3JsMB8GA1UdIwQYMBaAFFaE7LVxpedj2NtRBNb65vBI
UknOMA0GCSqGSIb3DQEBBQUAA4IBAQBZvf+2xUJE0ekxuNk30kPDj+5u9oI3jZyM
wvhKcs7AuRAbcxPtSOnVGNYl8By7DPvPun+U3Yci8540y143RgD+kz3jxIBaoW/o
c4+X61v6DBUtcBPEt+KkV6HIsZ61SZmc/Y1I2eoeEt6JYoLjEZMDLLvc1cK/+wpg
dUZSK4O9kjvIXqvsqIOlkmh/6puSugTNao2A7EIQr8ut0ZmzKzMyZ0BuQhJDnAPd
Kz5vh+5tmytUPKA8hUgmLWe94lMb7Uqq2wgZKsqun5DAWleKu81w7wEcOrjiiB+x
jeBHq7OnpWm+ccTOPCE6H4ZN4wWVS7biEBUdop/8HgXBPQHWAdjL
-----END CERTIFICATE-----`

// A Comodo intermediate CA certificate with issuer url, CRL url and OCSP url
var goodComodoCA = `-----BEGIN CERTIFICATE-----
MIIGCDCCA/CgAwIBAgIQKy5u6tl1NmwUim7bo3yMBzANBgkqhkiG9w0BAQwFADCB
hTELMAkGA1UEBhMCR0IxGzAZBgNVBAgTEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4G
A1UEBxMHU2FsZm9yZDEaMBgGA1UEChMRQ09NT0RPIENBIExpbWl0ZWQxKzApBgNV
BAMTIkNPTU9ETyBSU0EgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwHhcNMTQwMjEy
MDAwMDAwWhcNMjkwMjExMjM1OTU5WjCBkDELMAkGA1UEBhMCR0IxGzAZBgNVBAgT
EkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4GA1UEBxMHU2FsZm9yZDEaMBgGA1UEChMR
Q09NT0RPIENBIExpbWl0ZWQxNjA0BgNVBAMTLUNPTU9ETyBSU0EgRG9tYWluIFZh
bGlkYXRpb24gU2VjdXJlIFNlcnZlciBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEP
ADCCAQoCggEBAI7CAhnhoFmk6zg1jSz9AdDTScBkxwtiBUUWOqigwAwCfx3M28Sh
bXcDow+G+eMGnD4LgYqbSRutA776S9uMIO3Vzl5ljj4Nr0zCsLdFXlIvNN5IJGS0
Qa4Al/e+Z96e0HqnU4A7fK31llVvl0cKfIWLIpeNs4TgllfQcBhglo/uLQeTnaG6
ytHNe+nEKpooIZFNb5JPJaXyejXdJtxGpdCsWTWM/06RQ1A/WZMebFEh7lgUq/51
UHg+TLAchhP6a5i84DuUHoVS3AOTJBhuyydRReZw3iVDpA3hSqXttn7IzW3uLh0n
c13cRTCAquOyQQuvvUSH2rnlG51/ruWFgqUCAwEAAaOCAWUwggFhMB8GA1UdIwQY
MBaAFLuvfgI9+qbxPISOre44mOzZMjLUMB0GA1UdDgQWBBSQr2o6lFoL2JDqElZz
30O0Oija5zAOBgNVHQ8BAf8EBAMCAYYwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNV
HSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwGwYDVR0gBBQwEjAGBgRVHSAAMAgG
BmeBDAECATBMBgNVHR8ERTBDMEGgP6A9hjtodHRwOi8vY3JsLmNvbW9kb2NhLmNv
bS9DT01PRE9SU0FDZXJ0aWZpY2F0aW9uQXV0aG9yaXR5LmNybDBxBggrBgEFBQcB
AQRlMGMwOwYIKwYBBQUHMAKGL2h0dHA6Ly9jcnQuY29tb2RvY2EuY29tL0NPTU9E
T1JTQUFkZFRydXN0Q0EuY3J0MCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5jb21v
ZG9jYS5jb20wDQYJKoZIhvcNAQEMBQADggIBAE4rdk+SHGI2ibp3wScF9BzWRJ2p
mj6q1WZmAT7qSeaiNbz69t2Vjpk1mA42GHWx3d1Qcnyu3HeIzg/3kCDKo2cuH1Z/
e+FE6kKVxF0NAVBGFfKBiVlsit2M8RKhjTpCipj4SzR7JzsItG8kO3KdY3RYPBps
P0/HEZrIqPW1N+8QRcZs2eBelSaz662jue5/DJpmNXMyYE7l3YphLG5SEXdoltMY
dVEVABt0iN3hxzgEQyjpFv3ZBdRdRydg1vs4O2xyopT4Qhrf7W8GjEXCBgCq5Ojc
2bXhc3js9iPc0d1sjhqPpepUfJa3w/5Vjo1JXvxku88+vZbrac2/4EjxYoIQ5QxG
V/Iz2tDIY+3GH5QFlkoakdH368+PUq4NCNk+qKBR6cGHdNXJ93SrLlP7u3r7l+L4
HyaPs9Kg4DdbKDsx5Q5XLVq4rXmsXiBmGqW5prU5wfWYQ//u+aen/e7KJD2AFsQX
j4rBYKEMrltDR5FL1ZoXX/nUh8HCjLfn4g8wGTeGrODcQgPmlKidrv0PJFGUzpII
0fxQ8ANAe4hZ7Q7drNJ3gjTcBpUC2JD5Leo31Rpg0Gcg19hCC0Wvgmje3WYkN5Ap
lBlGGSW4gNfL1IYoakRwJiNiqZ+Gb7+6kHDSVneFeO/qJakXzlByjAA6quPbYzSf
+AZxAeKCINT+b72x
-----END CERTIFICATE-----`

func (suite *RevokeTestSuite) TestCRLCheckRevokedCert() {

	ctx := context.Background()

	// tests the case where the certificate doesn't contain extra attributes names
	var crt *x509.Certificate

	// tests the case of a revoked cert
	crt = ParseCert(revokedCert)

	// test multiple times to make sure that the function produces a steady result
	for i := 0; i < 100; i++ {

		err1 := CRLCheckRevokedCert(ctx, crt)

		suite.Equal("Your certificate has been revoked", err1.Error())
	}

	// tests the case of a non revoked cert
	crt = ParseCert(goodComodoCA)

	// test multiple times to make sure that the function produces a steady result
	for i := 0; i < 100; i++ {

		err2 := CRLCheckRevokedCert(ctx, crt)

		suite.Nil(err2)
	}

	// tests the case of an empty slice for CRLDPs
	crt = ParseCert(goodComodoCA)
	crt.CRLDistributionPoints = []string{}
	err3 := CRLCheckRevokedCert(ctx, crt)

	suite.Equal("Your certificate is invalid. No CRLDistributionPoints found on the certificate", err3.Error())

	// test the case of an invalid CRL URL
	crt = ParseCert(goodComodoCA)
	crt.CRLDistributionPoints = []string{"https://unknown/unknown"}
	err4 := CRLCheckRevokedCert(ctx, crt)

	suite.Equal("Could not access CRL https://unknown/unknown", err4.Error())
}

func TestRevokeTestSuite(t *testing.T) {
	LOGGER.SetOutput(ioutil.Discard)
	suite.Run(t, new(RevokeTestSuite))
}
