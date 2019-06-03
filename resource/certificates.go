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
	"intel/isecl/cms/constants"
	"intel/isecl/cms/setup"
	"intel/isecl/cms/utils"
	"intel/isecl/cms/validation"
	"io/ioutil"
	"math/big"
	"net/http"
	"regexp"
	"strings"
	"time"

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

	regexForCRLF := regexp.MustCompile(`\r?\n`)
	responseBodyBytes, err := ioutil.ReadAll(httpRequest.Body)
	if err != nil {
		log.Errorf("Cannot read http request body: %v", err)
		fmt.Println("Cannot read http request body")
		httpWriter.WriteHeader(http.StatusBadRequest)
	}

	csrInput := regexForCRLF.ReplaceAllString(string(responseBodyBytes), "")
	csrInput = strings.Replace(csrInput, "-----BEGIN CERTIFICATE REQUEST-----", "", -1)
	csrInput = strings.Replace(csrInput, "-----END CERTIFICATE REQUEST-----", "", -1)
	valid := validation.ValidateCertificateRequest(csrInput)
	if !valid {
		log.Errorf("Invalid CSR provided")
		fmt.Println("Invalid CSR provided")
		httpWriter.WriteHeader(http.StatusBadRequest)
		return
	}
	csrBase64Bytes, err := base64.StdEncoding.DecodeString(csrInput)
	csr, err := x509.ParseCertificateRequest(csrBase64Bytes)
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

	keyPair, err := tls.LoadX509KeyPair(constants.CMS_ROOT_CA_CERT, constants.CMS_ROOT_CA_KEY)

	if err != nil {
		log.Errorf("Cannot load key pair: %v", err)
		fmt.Println("Cannot load key pair")
		httpWriter.WriteHeader(http.StatusInternalServerError)
	}
	priv, _ := rsa.GenerateKey(rand.Reader, 3072)
	pub := &priv.PublicKey

	certificate, err := x509.CreateCertificate(rand.Reader, &certificateTemplate, &setup.RootCertificateTemplate, pub, keyPair.PrivateKey)
	if err != nil {
		log.Errorf("Cannot create certificate: %v", err)
		fmt.Println("Cannot create certificate")
		httpWriter.WriteHeader(http.StatusInternalServerError)
	}
	httpWriter.WriteHeader(http.StatusOK)
	httpWriter.Header().Add("Content-Type", "application/x-pem-file")
	pem.Encode(httpWriter, &pem.Block{Type: "CERTIFICATE", Bytes: certificate})
	return
}
