/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package resource

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"intel/isecl/cms/config"
	"intel/isecl/cms/constants"
	"intel/isecl/cms/tasks"
	"intel/isecl/cms/utils"
	"intel/isecl/cms/validation"
	"intel/isecl/lib/common/auth"
	"intel/isecl/lib/common/context"
	ct "intel/isecl/lib/common/types/aas"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
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
	RootCertificateTemplate := tasks.GetRootCACertDefaultTemplate(config)
	clientCRTTemplate := x509.Certificate{
		Signature:          clientCSR.Signature,
		SignatureAlgorithm: clientCSR.SignatureAlgorithm,

		PublicKeyAlgorithm: clientCSR.PublicKeyAlgorithm,
		PublicKey:          clientCSR.PublicKey,

		IPAddresses: clientCSR.IPAddresses,
		DNSNames:    clientCSR.DNSNames,

		SerialNumber: serialNumber,
		Issuer:       RootCertificateTemplate.Issuer,
		Subject:      clientCSR.Subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
	}

	if strings.EqualFold(certType, "TLS") {
		clientCRTTemplate.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageContentCommitment
		clientCRTTemplate.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
	} else if strings.EqualFold(certType, "Flavor-Signing") {
		clientCRTTemplate.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment
	} else if strings.EqualFold(certType, "JWT-Signing") {
		clientCRTTemplate.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageContentCommitment
	} else {
		log.Errorf("Invalid certType provided")
		httpWriter.WriteHeader(http.StatusBadRequest)
		httpWriter.Write([]byte("Invalid certType provided"))
		return
	}

	keyPair, err := tls.LoadX509KeyPair(constants.RootCACertPath, constants.RootCAKeyPath)
	if err != nil {
		log.Errorf("Cannot load TLS key pair: %v", err)
		httpWriter.WriteHeader(http.StatusInternalServerError)
		httpWriter.Write([]byte("Cannot load TLS key pair"))
	}

	certificate, err := x509.CreateCertificate(rand.Reader, &clientCRTTemplate, &RootCertificateTemplate, clientCSR.PublicKey, keyPair.PrivateKey)
	if err != nil {
		log.Errorf("Cannot create certificate: %v", err)
		httpWriter.WriteHeader(http.StatusInternalServerError)
		httpWriter.Write([]byte("Cannot create certificate"))
	}
	httpWriter.Header().Add("Content-Type", "application/x-pem-file")
	httpWriter.WriteHeader(http.StatusOK)
	pem.Encode(httpWriter, &pem.Block{Type: "CERTIFICATE", Bytes: certificate})
	return
}
