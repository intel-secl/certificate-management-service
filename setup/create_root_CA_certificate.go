package setup

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"os"
	"strconv"
	"time"

	log "github.com/sirupsen/logrus"

	csetup "intel/isecl/lib/common/setup"
)

//CreateRootCACertificate is a setup task to create root CA certificate and root key pair
type CreateRootCACertificate struct{}

//Run will generate a rootCA certificate and key pair and store them in cms config dir
func (createRootCACertificate CreateRootCACertificate) Run(c csetup.Context) {

	priv, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		log.Fatalf("failed to generate private key: %s", err)
	}

	if err != nil {
		log.Fatalf("failed to generate serial number: %s", err)
	}

	certValidity, err := strconv.Atoi(os.Getenv("CMS_CA_CERT_VALIDITY"))
	if err != nil {
		log.Errorf("Error getting certificate validity: %v", err)
		// Set to default
		certValidity = 5
	}

	certificateTemplate := x509.Certificate{
		Subject: pkix.Name{
			CommonName: "CMSCA",
		},
		Issuer: pkix.Name{
			CommonName: "CMSCA",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(certValidity, 0, 0),

		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certificateBytes, err := x509.CreateCertificate(rand.Reader, &certificateTemplate, &certificateTemplate, &priv.PublicKey, priv)
	if err != nil {
		log.Fatalf("Failed to create certificate: %s", err)
	}

	certOut, err := os.Create("/opt/cms/config/rootCA.crt")
	if err != nil {
		log.Fatalf("failed to open rootCA.crt file for writing: %s", err)
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certificateBytes}); err != nil {
		log.Fatalf("failed to write data to rootCA.crt: %s", err)
	}
	if err := certOut.Close(); err != nil {
		log.Fatalf("error closing rootCA.crt: %s", err)
	}

	keyOut, err := os.OpenFile("/opt/cms/config/rootCA.key", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Print("failed to open rootCA.key for writing:", err)
		return
	}
	if err := pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)}); err != nil {
		log.Fatalf("failed to write data to rootCA.key: %s", err)
	}
	if err := keyOut.Close(); err != nil {
		log.Fatalf("error closing rootCA.key: %s", err)
	}
}

// Validate checks whether or not the CreateRootCACertificate task was successful
func (createRootCACertificate CreateRootCACertificate) Validate(c csetup.Context) {
}
