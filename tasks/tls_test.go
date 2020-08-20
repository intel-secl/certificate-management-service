/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
        "crypto/x509"
        "encoding/pem"
	"intel/isecl/cms/v3/config"
	"intel/isecl/lib/common/v3/setup"
	"os"
	"io/ioutil"
        "testing"

	"github.com/stretchr/testify/assert"
)


func testGetRootCACert() (*x509.Certificate){
        block, _ := pem.Decode([]byte(`
-----BEGIN CERTIFICATE-----
MIIELDCCApSgAwIBAgIBADANBgkqhkiG9w0BAQwFADBHMQswCQYDVQQGEwJVUzEL
MAkGA1UECBMCU0YxCzAJBgNVBAcTAlNDMQ4wDAYDVQQKEwVJTlRFTDEOMAwGA1UE
AxMFQ01TQ0EwHhcNMTkwOTMwMjM1MzQxWhcNMjQwOTMwMjM1MzQxWjBHMQswCQYD
VQQGEwJVUzELMAkGA1UECBMCU0YxCzAJBgNVBAcTAlNDMQ4wDAYDVQQKEwVJTlRF
TDEOMAwGA1UEAxMFQ01TQ0EwggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIB
gQCXVtwJjlp7srBwSRFJQbfpLRQJYAbAWVLPiRNrN4j4E9YOtNNAb3QZv/nL27ZJ
55qxT7sN6loejA2AdVaO8ulAsqfz4gilIsvqsyRq1pBXGdEfjRhC51WXe/uuK6Ej
lqUUQ9C13V5SlM0QE6P9i/r2qvkeNSmNKADrz4SxS3r9dimiHn12kO4jDhc1pHRp
m09u6BAanVhaS9Yme/aWoboNIpkvZuOikBZCFKoK7TtUAE4++ZoCX02Cr++zf9X3
+dQ83XMHqNdm5GWQnsDPdtjMz+UwQ0cfbvTP2u7PenssFXBfiHQDXDTqEr1JuFmD
31XAGuA89edASatJbzio9sU5UxDgjmHaRQQG+h8kvTBBbDCOKeUjr9CcYocYwCtT
rS5FiSkIXp35skTTJ00HE0CkQUQNcc0i/RTIpf1pOVWnOOnabbGUvJNUegw+MnMN
lJux7vH3ky+/S5v7ueN1gm+pMgAPj6f6aoz3RJFx2kL3eRklDxW1mcrgSsolg4Y7
rvkCAwEAAaMjMCEwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wDQYJ
KoZIhvcNAQEMBQADggGBAB/YOX4G87pLvvS0olDq9ZB+REtNq1Gw6YhQ1s+owHST
GpUiCMFwe+tbVZksEzRjgcq485jc5stWhLNv/EuFUmHieW1+lJX5O2OgUvITsr0E
Tx0N80Ki0Y5xdXO5iAnAbk4SgQUsPh0Ylin/TB70NuGAIKd/r2Af7E93QdEBbfp0
qVMvHmAonWWmWHxgi5f+12gPMulxcvfHebQkjN2oSy7ac710cqzVhp1IZpO1Utav
fLj/upk05R3Dn7wmQt19+0PYwwUWGVW5dIb8h0s4amIaV1KGBpCupu1tOP+Iqn1u
uch/aCYAqEPVSY50N4GYmTirK4p3wsugSactvIJN19BbLNeWXHTtmETx3oi0HIUp
P4oH3l5zK4b+X9cVwu41iAHVGYtvJ/Okc55qmAflXpz3HekUsQTG46q3SPIyZwtO
MmCeWomw5+oedrhhHuuyeocwfhyAXONS0WH5hzyJ9smTZXqyad4jwgwdlrPHyDI/
AjYgFij/70d+Pv4EG+r2zA==
-----END CERTIFICATE-----
        `))
        cert, _ := x509.ParseCertificate(block.Bytes)
        return cert
}

func testGetPrivateRootkey() (interface{}){
        block, _ := pem.Decode([]byte (`
-----BEGIN PKCS8 PRIVATE KEY-----
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
gzYhnLbrMmEmT6k3fimA5Ck=
-----END PKCS8 PRIVATE KEY-----
`))
        privKey,_ := x509.ParsePKCS8PrivateKey(block.Bytes)
        return privKey
}

func TestTlsCertCreation(t *testing.T) {
        log.Trace("tasks/tls_test:TestTlsCertCreation() Entering")
	defer log.Trace("tasks/tls_test:TestTlsCertCreation() Leaving")

	assert := assert.New(t)
        CreateSerialNumberFileAndJWTDir()

        temp, _ := ioutil.TempFile("", "config.yml")
        temp.WriteString("keyalgorithm: rsa\nkeyalgorithmlength: 3072\n")
        defer os.Remove(temp.Name())
        c := config.Load(temp.Name())

        ca := Root_Ca{
                Flags:         nil,
                ConsoleWriter: os.Stdout,
                Config: c,
        }

        ctx := setup.Context{}
        err := ca.Run(ctx)
        assert.NoError(err)

	ts := TLS{
		Flags:         []string{""},
		ConsoleWriter: os.Stdout,
		Config: c,
        }

        //TODO: need to fix this test. New parameters.. need to pass in issuing CA cert and key
	keyData, certData, err := createTLSCert(ts, "intel.com", testGetRootCACert(), testGetPrivateRootkey())
	assert.NoError(err)
	_, err = x509.ParsePKCS8PrivateKey(keyData)
	assert.NoError(err)
	cert, err := x509.ParseCertificate(certData)
	assert.NoError(err)
	assert.Contains(cert.DNSNames, "intel.com")
	assert.NoError(cert.VerifyHostname("intel.com"))
}

func TestTlsSetupTaskRun(t *testing.T){
        log.Trace("tasks/tls_test:TestTlsSetupTaskRun() Entering")
	defer log.Trace("tasks/tls_test:TestTlsSetupTaskRun() Leaving")

	assert := assert.New(t)
        CreateSerialNumberFileAndJWTDir()

        temp, _ := ioutil.TempFile("", "config.yml")
        temp.WriteString("keyalgorithm: rsa\nkeyalgorithmlength: 3072\n")
        defer os.Remove(temp.Name())
        c := config.Load(temp.Name())

        ca := Root_Ca{
                Flags:         nil,
                ConsoleWriter: os.Stdout,
                Config: c,
        }

        ctx := setup.Context{}
        err := ca.Run(ctx)
        assert.NoError(err)

        interCA := Intermediate_Ca{
                Flags:         nil,
                ConsoleWriter: os.Stdout,
                Config: c,
        }
        err = interCA.Run(ctx)

        ts := TLS{
                Flags:         []string{""},
                ConsoleWriter: os.Stdout,
                Config: c,
        }
	err = ts.Run(ctx)
	assert.NoError(err)
}

func TestOutboundHost(t *testing.T) {
        log.Trace("tasks/tls_test:TestOutboundHost() Entering")
	defer log.Trace("tasks/tls_test:TestOutboundHost() Leaving")

	host, err := outboundHost()
	assert.NoError(t, err)
	assert.NotNil(t, host)
}
