package resource

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"intel/isecl/cms/setup"
	"intel/isecl/cms/validation"
	"io/ioutil"
	"math/big"
	"net/http"
	"regexp"
	"time"
	"intel/isecl/cms/utils"

	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
	//"io/ioutil"
)

// SetCertificatesEndpoints is used to set the endpoints for certificate handling APIs
func SetCertificatesEndpoints(router *mux.Router) {
	router.HandleFunc("", GetCertificates).Methods("POST")
	router.Use(validation.JwtAuthentication)
}

//GetCertificates is used to get the JWT Signing/TLS certificate upon JWT valildation
func GetCertificates(httpWriter http.ResponseWriter, httpRequest *http.Request) {

	//TODO: Provide generic path for root CA certificate
	const rootCACertificateFile = "/var/lib/cms/rootCA.crt"
	const rootCAPrivateKeyFile = "/var/lib/cms/rootCA.key"

	regexForCRLF := regexp.MustCompile(`\r?\n`)
	responseBodyBytes, err := ioutil.ReadAll(httpRequest.Body)
	if err != nil {
		log.Errorf("Cannot read http request body: %v", err)
		fmt.Println("Cannot read http request body")
	}

	csrInput := regexForCRLF.ReplaceAllString(string(responseBodyBytes), "")
	valid := validation.ValidateCertificateRequest(csrInput)
	if !valid {
		log.Errorf("Invalid CSR provided")
		fmt.Println("Invalid CSR provided")
	}
	csrBase64Bytes, err := base64.StdEncoding.DecodeString(csrInput)
	csr, err := x509.ParseCertificateRequest(csrBase64Bytes)
	fmt.Println(csr.Subject)
	fmt.Println(csr.Extensions)

	certificateTemplate := x509.Certificate{
		SerialNumber: big.NewInt(0),
		Subject: pkix.Name{
			CommonName: csr.Subject.CommonName,
		},
		Issuer: pkix.Name{
			CommonName: "CMSCA",
		},

		SignatureAlgorithm:    x509.SHA384WithRSA,
		PublicKeyAlgorithm:    x509.RSA,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		BasicConstraintsValid: true,
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{},
		KeyUsage:              x509.KeyUsageDigitalSignature,
	}

	for _, extension := range csr.Extensions {
		if extension.Value[3] == 160 {
			certificateTemplate.KeyUsage |= x509.KeyUsageKeyEncipherment
		}
	}

	serialNumber, err := utils.GetNextSerialNumber()
	if err != nil {
		log.Errorf("Failed to read next Serial Number: %s", err)
	} else {
		certificateTemplate.SerialNumber = serialNumber
	}

	if httpRequest.Header.Get("Accept") != "application/x-pem-file" || httpRequest.Header.Get("Content-Type") != "application/x-pem-file" {
		httpWriter.WriteHeader(http.StatusNotAcceptable)
		return
	}

	keyPair, err := tls.LoadX509KeyPair(rootCACertificateFile, rootCAPrivateKeyFile)

	if err != nil {
		log.Errorf("Cannot load key pair: %v", err)
		fmt.Println("Cannot load key pair")
	}
	priv, _ := rsa.GenerateKey(rand.Reader, 3072)
	pub := &priv.PublicKey

	certificate, err := x509.CreateCertificate(rand.Reader, &certificateTemplate, &setup.RootCertificateTemplate, pub, keyPair.PrivateKey)
	if err != nil {
		log.Errorf("Cannot create certificate: %v", err)
		fmt.Println("Cannot create certificate")
	}
	httpWriter.WriteHeader(http.StatusOK)
	httpWriter.Header().Add("Content-Type", "application/x-pem-file")
	pem.Encode(httpWriter, &pem.Block{Type: "CERTIFICATE", Bytes: certificate})
	return
}
