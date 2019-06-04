package setup

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"intel/isecl/cms/utils"
	"math/big"
	"os"
	"time"

	log "github.com/sirupsen/logrus"

	"intel/isecl/cms/config"
	"intel/isecl/cms/constants"
	csetup "intel/isecl/lib/common/setup"
)

//RootCertificateTemplate is a template for root CA certificate
var RootCertificateTemplate = x509.Certificate{
	SignatureAlgorithm: x509.SHA384WithRSA,
	Subject: pkix.Name{
		CommonName:   "CMSCA",
		Country:      []string{},
		Province:     []string{},
		Locality:     []string{},
		Organization: []string{},
	},
	Issuer: pkix.Name{
		CommonName: "CMSCA",
	},
	NotBefore: time.Now(),
	NotAfter:  time.Now().AddDate(5, 0, 0),

	KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	BasicConstraintsValid: true,
	IsCA:                  true,
}

//CreateRootCACertificate is a setup task to create root CA certificate and root key pair
type CreateRootCACertificate struct{}

//Run will generate a rootCA certificate and key pair and store them in cms config dir
func (createRootCACertificate CreateRootCACertificate) Run(c csetup.Context) error {

	priv, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		log.Errorf("Failed to generate root CA key pair: %s", err)
		return errors.New("Failed to generate root CA key pair")
	}

	config.LoadConfiguration()
	var serialNumber = big.NewInt(0)
	RootCertificateTemplate.SerialNumber = serialNumber
	err = utils.WriteSerialNumber(serialNumber)
	if err != nil {
		log.Errorf("Cannot write to Serial Number file")
		return errors.New("Cannot write to Serial Number file")
	}

	certValidity := config.Configuration.CACertValidity
	if certValidity == 0 {
		log.Errorf("Error getting certificate validity: %v", err)
		// Set to default
		certValidity = 5
	}
	RootCertificateTemplate.NotAfter = time.Now().AddDate(certValidity, 0, 0)

	if config.Configuration.Organization != "" {
		RootCertificateTemplate.Subject.Organization = append(RootCertificateTemplate.Subject.Organization, config.Configuration.Organization)
	} else {
		RootCertificateTemplate.Subject.Organization = append(RootCertificateTemplate.Subject.Organization, "INTEL")
	}

	if config.Configuration.Country != "" {
		RootCertificateTemplate.Subject.Country = append(RootCertificateTemplate.Subject.Country, config.Configuration.Country)
	} else {
		RootCertificateTemplate.Subject.Country = append(RootCertificateTemplate.Subject.Country, "US")
	}

	if config.Configuration.Province != "" {
		RootCertificateTemplate.Subject.Province = append(RootCertificateTemplate.Subject.Province, config.Configuration.Province)
	} else {
		RootCertificateTemplate.Subject.Province = append(RootCertificateTemplate.Subject.Province, "CA")
	}

	if config.Configuration.Locality != "" {
		RootCertificateTemplate.Subject.Locality = append(RootCertificateTemplate.Subject.Locality, config.Configuration.Locality)
	} else {
		RootCertificateTemplate.Subject.Province = append(RootCertificateTemplate.Subject.Locality, "SC")
	}

	certificateBytes, err := x509.CreateCertificate(rand.Reader, &RootCertificateTemplate, &RootCertificateTemplate, &priv.PublicKey, priv)
	if err != nil {
		log.Errorf("Failed to create certificate: %s", err)
		return errors.New("Failed to create certificate")
	}

	certOut, err := os.Create(constants.CMS_ROOT_CA_CERT)
	if err != nil {
		log.Errorf("Failed to open root CA certificate file: %s", err)
		return errors.New("Failed to open root CA certificate file")
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certificateBytes}); err != nil {
		log.Errorf("Failed to write data to rootCA.crt: %s", err)
		return errors.New("Failed to write data to root CA certificate file")
	}
	if err := certOut.Close(); err != nil {
		log.Errorf("Error closing root CA certificate file: %s", err)
		return errors.New("Error closing root CA certificate file")
	}

	keyOut, err := os.OpenFile(constants.CMS_ROOT_CA_KEY, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Print("Failed to open root CA key file:", err)
		return errors.New("Failed to open root CA key file")
	}
	if err := pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)}); err != nil {
		log.Errorf("Failed to write data to root CA key file: %s", err)
		return errors.New("Failed to write data to root CA key file")
	}
	if err := keyOut.Close(); err != nil {
		log.Errorf("Error closing root CA key file: %s", err)
		return errors.New("Error closing root CA key file")
	}
	return nil
}

// Validate checks whether or not the CreateRootCACertificate task was successful
func (createRootCACertificate CreateRootCACertificate) Validate(c csetup.Context) error {
	return nil
}
