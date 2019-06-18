/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
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
	"intel/isecl/cms/utils"
	"intel/isecl/cms/config"
	"intel/isecl/cms/validation"
	"intel/isecl/cms/tasks"
	"io/ioutil"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
	//"io/ioutil"
)

// SetCertificates is used to set the endpoints for certificate handling APIs
func SetCertificates(router *mux.Router, config *config.Configuration) {
	router.HandleFunc("/certificates", func(w http.ResponseWriter, r *http.Request) {
		GetCertificates(w, r, config)
	}).Methods("POST")
	router.Use(validation.JwtAuthentication)
}

//GetCertificates is used to get the JWT Signing/TLS certificate upon JWT valildation
func GetCertificates(httpWriter http.ResponseWriter, httpRequest *http.Request, config *config.Configuration) {

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
	err = validation.ValidateCertificateRequest(config, csrInput)
	if err != nil {
		log.Errorf("Invalid CSR provided: %v", err)
		httpWriter.WriteHeader(http.StatusBadRequest)
		httpWriter.Write([]byte("Invalid CSR provided: " + err.Error()))
		return
	}
	csrBase64Bytes, err := base64.StdEncoding.DecodeString(csrInput)
	csr, err := x509.ParseCertificateRequest(csrBase64Bytes)
	certificateTemplate := x509.Certificate{
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
		if len(extension.Value) == 4 && extension.Value[3] == 160 {
			certificateTemplate.KeyUsage |= x509.KeyUsageKeyEncipherment
		}
	}

	serialNumber, err := utils.GetNextSerialNumber()
	if err != nil {
		log.Errorf("Failed to read next Serial Number: %s", err)
		httpWriter.WriteHeader(http.StatusInternalServerError)
		httpWriter.Write([]byte("Failed to read next Serial Number" + err.Error()))
		return
	} else {
		certificateTemplate.SerialNumber = serialNumber
	}

	if httpRequest.Header.Get("Accept") != "application/x-pem-file" || httpRequest.Header.Get("Content-Type") != "application/x-pem-file" {
		log.Errorf("Accept type not supported")
		httpWriter.WriteHeader(http.StatusNotAcceptable)
		httpWriter.Write([]byte("Accept type not supported"))
		return
	}

	keyPair, err := tls.LoadX509KeyPair(constants.RootCACertPath, constants.RootCAKeyPath)

	if err != nil {
		log.Errorf("Cannot load TLS key pair: %v", err)
		httpWriter.WriteHeader(http.StatusInternalServerError)
		httpWriter.Write([]byte("Cannot load TLS key pair"))
	}
	priv, _ := rsa.GenerateKey(rand.Reader, 3072)
	pub := &priv.PublicKey
	
	certificate, err := x509.CreateCertificate(rand.Reader, &certificateTemplate, &tasks.RootCertificateTemplate, pub, keyPair.PrivateKey)
	if err != nil {
		log.Errorf("Cannot create certificate: %v", err)
		httpWriter.WriteHeader(http.StatusInternalServerError)
		httpWriter.Write([]byte("Cannot create certificate"))
	}
	httpWriter.WriteHeader(http.StatusOK)
	httpWriter.Header().Add("Content-Type", "application/x-pem-file")
	pem.Encode(httpWriter, &pem.Block{Type: "CERTIFICATE", Bytes: certificate})
	return
}
