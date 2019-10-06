/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package resource

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"intel/isecl/cms/config"
	"intel/isecl/cms/constants"
	"intel/isecl/lib/common/crypt"
	"intel/isecl/cms/utils"
	"intel/isecl/cms/validation"
	"intel/isecl/lib/common/auth"
	"intel/isecl/lib/common/context"
	ct "intel/isecl/lib/common/types/aas"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
	"regexp"
	v "intel/isecl/lib/common/validation"
	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
)

// SetCertificates is used to set the endpoints for certificate handling APIs
func SetCertificates(router *mux.Router, config *config.Configuration) {
	router.HandleFunc("", func(w http.ResponseWriter, r *http.Request) {
		GetCertificates(w, r, config)
	}).Methods("POST")
}

//GetCertificates is used to get the JWT Signing/TLS certificate upon JWT valildation
func GetCertificates(httpWriter http.ResponseWriter, httpRequest *http.Request, config *config.Configuration) {
	privileges, err := context.GetUserRoles(httpRequest)
	if err != nil {
		httpWriter.WriteHeader(http.StatusInternalServerError)
		httpWriter.Write([]byte("Could not get user roles from http context"))
		return
	}

	ctxMap, foundRole := auth.ValidatePermissionAndGetRoleContext(privileges,
		[]ct.RoleInfo{ct.RoleInfo{Service: constants.ServiceName, Name: constants.CertApproverGroupName}},
		true)
	if !foundRole {
		httpWriter.WriteHeader(http.StatusUnauthorized)
		return
	}

	if httpRequest.Header.Get("Accept") != "application/x-pem-file" || httpRequest.Header.Get("Content-Type") != "application/x-pem-file" {
		log.Errorf("Accept type not supported")
		httpWriter.WriteHeader(http.StatusNotAcceptable)
		httpWriter.Write([]byte("Accept type not supported"))
		return
	}

	// TODO: this is a POST.. we should not be having Query parameters here. If we need to distinguish the type of 
	// certificate requested, this should be part of the path and not a query parameter. I beleive we should be
	// able to set up the router so that we have the type in the path.
	certType := httpRequest.URL.Query().Get("certType")
	if (certType == "") {
		log.Errorf("Accept type not supported")
		httpWriter.Write([]byte("Query parameter certType missing"))
		httpWriter.WriteHeader(http.StatusBadRequest)
		return
	}
	certTypeVal := []string{certType}
	if validateErr := v.ValidateStrings(certTypeVal); validateErr != nil {
		log.Errorf("Accept type not supported")
		httpWriter.Write([]byte("Query parameter certType is in invalid format"))
		httpWriter.WriteHeader(http.StatusBadRequest)
		return
	}

	responseBodyBytes, err := ioutil.ReadAll(httpRequest.Body)
	if err != nil {
		log.Errorf("Cannot read http request body: %v", err)
		fmt.Println("Cannot read http request body")
		httpWriter.Write([]byte("Cannot read http request body"))
		httpWriter.WriteHeader(http.StatusBadRequest)
		return
	}

	// TODO: why are we regular expression matching the CSR? This is should be handled below
	// with the x509.ParseCertificateRequest. If there is a problem with the CSR, it should be
	// handled there. If our intention here is input validation, we should just check for a
	// maximum reasonable size
	re := regexp.MustCompile(`\r?\n`)
	err = v.ValidatePemEncodedKey(re.ReplaceAllString(string(responseBodyBytes),""))
	if err != nil {
		log.Errorf("Invalid certificate signing request : %v", err)
		httpWriter.WriteHeader(http.StatusBadRequest)
		httpWriter.Write([]byte("Invalid certificate signing request provided"))
		return
	}

	pemBlock, _ := pem.Decode(responseBodyBytes)
	if pemBlock == nil {
		log.Errorf("Failed to decode pem: %s", err)
		httpWriter.WriteHeader(http.StatusBadRequest) 
		httpWriter.Write([]byte("Failed to decode pem" + err.Error()))
		return
	}

	clientCSR, err := x509.ParseCertificateRequest(pemBlock.Bytes)
	if err != nil {
		log.Errorf("Invalid CSR provided: %v", err)
		httpWriter.WriteHeader(http.StatusBadRequest)
		httpWriter.Write([]byte("Invalid CSR provided: " + err.Error()))
		return
	}

	err = validation.ValidateCertificateRequest(config, clientCSR, certType, ctxMap)
	if err != nil {
		log.Errorf("Invalid CSR provided: %v", err)
		httpWriter.WriteHeader(http.StatusBadRequest)
		httpWriter.Write([]byte("Invalid CSR provided: " + err.Error()))
		return
	}

	serialNumber, err := utils.GetNextSerialNumber()
	if err != nil {
		log.Errorf("Failed to read next Serial Number: %s", err)
		httpWriter.WriteHeader(http.StatusInternalServerError)
		httpWriter.Write([]byte("Failed to read next Serial Number" + err.Error()))
		return
	}

	clientCRTTemplate := x509.Certificate{
		Signature:          clientCSR.Signature,
		SignatureAlgorithm: clientCSR.SignatureAlgorithm,

		PublicKeyAlgorithm: clientCSR.PublicKeyAlgorithm,
		PublicKey:          clientCSR.PublicKey,


		SerialNumber: serialNumber,
		Subject:      clientCSR.Subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
	}

	// TODO: is the certificate requested is not a TLS certificate, we need to make sure that there is no SAN list
	// in the CSR and that the the CN is not in the form of a domain name/ IP address

	var issuingCa string

	if strings.EqualFold(certType, "TLS") {
		issuingCa = constants.Tls
		clientCRTTemplate.DNSNames =  clientCSR.DNSNames
		clientCRTTemplate.IPAddresses = clientCSR.IPAddresses

		clientCRTTemplate.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageContentCommitment
		clientCRTTemplate.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
	} else if strings.EqualFold(certType, "Flavor-Signing") || strings.EqualFold(certType, "JWT-Signing") || strings.EqualFold(certType, "Signing") {
		issuingCa = constants.Signing
		clientCRTTemplate.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment
	} else if strings.EqualFold(certType, "TLS-Client") {
		issuingCa = constants.TlsClient
		clientCRTTemplate.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment
		clientCRTTemplate.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	
		// TODO: should we be supporting signing CA over REST API? This seems like a dangerous proposition.
		// This should really be done by an administrator on the console. Not over REST API
	} else if strings.EqualFold(certType, "Signing-CA") {
		issuingCa = constants.Root
		clientCRTTemplate.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageContentCommitment
	} else {
		log.Errorf("Invalid certType provided")
		httpWriter.WriteHeader(http.StatusBadRequest)
		httpWriter.Write([]byte("Invalid certType provided"))
		return
	}
	caAttr := constants.GetCaAttribs(issuingCa)

	caCert, caPrivKey, err := crypt.LoadX509CertAndPrivateKey(caAttr.CertPath, caAttr.KeyPath)
	if err != nil {
		log.Errorf("cannot load Issuing CA - err : %v", err)
		httpWriter.WriteHeader(http.StatusInternalServerError)
		httpWriter.Write([]byte("Cannot load Issuing CA"))
	}

	certificate, err := x509.CreateCertificate(rand.Reader, &clientCRTTemplate, caCert, clientCSR.PublicKey, caPrivKey)
	if err != nil {
		log.Errorf("cannot create certificate: %v", err)
		httpWriter.WriteHeader(http.StatusInternalServerError)
		httpWriter.Write([]byte("Cannot create certificate"))
	}
	httpWriter.Header().Add("Content-Type", "application/x-pem-file")
	httpWriter.WriteHeader(http.StatusOK)
	// encode the certificate first
	pem.Encode(httpWriter, &pem.Block{Type: "CERTIFICATE", Bytes: certificate})
	// include the issuing CA as well since clients would need the entire chain minus the root.
	pem.Encode(httpWriter, &pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw})
	return
}
