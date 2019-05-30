package setup

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"time"

	log "github.com/sirupsen/logrus"

	csetup "intel/isecl/lib/common/setup"
)

//CreateTLSCertificate is a setup task to create root CA certificate and root key pair
type CreateTLSCertificate struct{}

//Run will generate a TLS certificate and key pair and store them in cms config dir
func (createTLSCertificate CreateTLSCertificate) Run(c csetup.Context) error {

	const rootCACertificateFile = "/var/lib/cms/rootCA.crt"
	const rootCAPrivateKeyFile = "/var/lib/cms/rootCA.key"
	priv, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		log.Fatalf("failed to generate private key: %s", err)
	}

	if err != nil {
		log.Fatalf("failed to generate serial number: %s", err)
	}

	certificateTemplate := x509.Certificate{
		SerialNumber:       big.NewInt(0),
		SignatureAlgorithm: x509.SHA384WithRSA,
		Subject: pkix.Name{
			CommonName: "CMS",
		},
		Issuer: pkix.Name{
			CommonName: "CMSCA",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(1, 0, 0),

		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
	}

	keyPair, err := tls.LoadX509KeyPair(rootCACertificateFile, rootCAPrivateKeyFile)
	if err != nil {
		log.Fatalf("Failed to load key pair: %s", err)
	}

	certificateBytes, err := x509.CreateCertificate(rand.Reader, &certificateTemplate, &RootCertificateTemplate, &priv.PublicKey, keyPair.PrivateKey)
	if err != nil {
		log.Fatalf("Failed to create certificate: %s", err)
	}

	certOut, err := os.Create("/var/lib/cms/Tls.crt")
	if err != nil {
		log.Fatalf("failed to open rootCA.crt file for writing: %s", err)
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certificateBytes}); err != nil {
		log.Fatalf("failed to write data to rootCA.crt: %s", err)
	}
	if err := certOut.Close(); err != nil {
		log.Fatalf("error closing rootCA.crt: %s", err)
	}

	keyOut, err := os.OpenFile("/var/lib/cms/Tls.key", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Print("failed to open rootCA.key for writing:", err)
		return nil
	}
	if err := pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)}); err != nil {
		log.Fatalf("failed to write data to Tls.key: %s", err)
	}
	if err := keyOut.Close(); err != nil {
		log.Fatalf("error closing Tls.key: %s", err)
	}
	return nil
}

// Validate checks whether or not the CreateTLSCertificate task was successful
func (createTLSCertificate CreateTLSCertificate) Validate(c csetup.Context) error {
	return nil
}
