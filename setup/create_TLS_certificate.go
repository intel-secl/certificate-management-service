package setup

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"intel/isecl/cms/constants"
	"intel/isecl/cms/utils"
	"os"
	"time"

	log "github.com/sirupsen/logrus"

	csetup "intel/isecl/lib/common/setup"
)

//CreateTLSCertificate is a setup task to create root CA certificate and root key pair
type CreateTLSCertificate struct{}

//Run will generate a TLS certificate and key pair and store them in cms config dir
func (createTLSCertificate CreateTLSCertificate) Run(c csetup.Context) error {

	const rootCACertificateFile = constants.CMS_ROOT_CA_CERT
	const rootCAPrivateKeyFile = constants.CMS_ROOT_CA_KEY
	priv, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		log.Errorf("Failed to generate TLS key pair: %s", err)
		return errors.New("Failed to generate TLS key pair")
	}

	certificateTemplate := x509.Certificate{
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
		log.Errorf("Failed to load key pair: %s", err)
		return errors.New("Failed to load key pair")
	}
	serialNumber, err := utils.GetNextSerialNumber()
	if err != nil {
		log.Errorf("Failed to read next Serial Number: %s", err)
		return errors.New("Failed to read next Serial Number")
	} else {
		certificateTemplate.SerialNumber = serialNumber
	}

	certificateBytes, err := x509.CreateCertificate(rand.Reader, &certificateTemplate, &RootCertificateTemplate, &priv.PublicKey, keyPair.PrivateKey)
	if err != nil {
		log.Errorf("Failed to create TLS certificate: %s", err)
		return errors.New("Failed to create certificate")
	}

	certOut, err := os.Create(constants.CMS_TLS_CERT)
	if err != nil {
		log.Errorf("Failed to open TLS certificate file: %s", err)
		return errors.New("Failed to open root CA certificate file")
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certificateBytes}); err != nil {
		log.Errorf("Failed to write data to TLS certificate file: %s", err)
		return errors.New("Failed to write data to TLS certificate file")
	}
	if err := certOut.Close(); err != nil {
		log.Errorf("Error closing TLS certificate file: %s", err)
		return errors.New("Error closing TLS certificate file")
	}

	keyOut, err := os.OpenFile(constants.CMS_TLS_KEY, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Errorf("Failed to open TLS key file: %s", err)
		return errors.New("Failed to open TLS key file")
	}
	if err := pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)}); err != nil {
		log.Errorf("Failed to write data to TLS key file: %s", err)
		return errors.New("Failed to write data to TLS key file")
	}
	if err := keyOut.Close(); err != nil {
		log.Errorf("Error closing TLS key file: %s", err)
		return errors.New("Error closing TLS key file")
	}
	return nil
}

// Validate checks whether or not the CreateTLSCertificate task was successful
func (createTLSCertificate CreateTLSCertificate) Validate(c csetup.Context) error {
	return nil
}
