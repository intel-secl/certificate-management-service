/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package resource

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"intel/isecl/cms/v3/config"
	"intel/isecl/cms/v3/constants"
	"intel/isecl/lib/common/v3/crypt"
	"intel/isecl/cms/v3/utils"
	"intel/isecl/cms/v3/validation"
	"intel/isecl/lib/common/v3/auth"
	"intel/isecl/lib/common/v3/context"
	ct "intel/isecl/lib/common/v3/types/aas"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
	v "intel/isecl/lib/common/v3/validation"
	"github.com/gorilla/mux"
	commLogMsg "intel/isecl/lib/common/v3/log/message"
)

// SetCertificates is used to set the endpoints for certificate handling APIs
func SetCertificates(router *mux.Router, config *config.Configuration) {
	log.Trace("resource/certificates:SetCertificates() Entering")
	defer log.Trace("resource/certificates:SetCertificates() Leaving")

	router.HandleFunc("", func(w http.ResponseWriter, r *http.Request) {
		GetCertificates(w, r, config)
	}).Methods("POST")
}

//GetCertificates is used to get the JWT Signing/TLS certificate upon JWT valildation
func GetCertificates(httpWriter http.ResponseWriter, httpRequest *http.Request, config *config.Configuration) {
	log.Trace("resource/certificates:GetCertificates() Entering")
	defer log.Trace("resource/certificates:GetCertificates() Leaving")

	privileges, err := context.GetUserRoles(httpRequest)
	if err != nil {
		slog.WithError(err).Warn("resource/certificates:GetCertificates() Failed to read roles and permissions")
		slog.Tracef("%+v",err)
		httpWriter.WriteHeader(http.StatusInternalServerError)
		httpWriter.Write([]byte("Could not get user roles from http context"))
		return
	}

	ctxMap, foundRole := auth.ValidatePermissionAndGetRoleContext(privileges,
		[]ct.RoleInfo{ct.RoleInfo{Service: constants.ServiceName, Name: constants.CertApproverGroupName}},
		true)
	if !foundRole {
		slog.Warning(commLogMsg.UnauthorizedAccess)
		httpWriter.WriteHeader(http.StatusUnauthorized)
		return
	}

	// TODO: this is a POST.. we should not be having Query parameters here. If we need to distinguish the type of 
	// certificate requested, this should be part of the path and not a query parameter. I beleive we should be
	// able to set up the router so that we have the type in the path.
	certType := httpRequest.URL.Query().Get("certType")
	if certType == "" {
		slog.Warning(commLogMsg.InvalidInputBadParam)
		log.Error("resource/certificates:GetCertificates() Query parameter certType missing")
		httpWriter.Write([]byte("Query parameter certType missing"))
		httpWriter.WriteHeader(http.StatusBadRequest)
		return
	}
	certTypeVal := []string{certType}
	if validateErr := v.ValidateStrings(certTypeVal); validateErr != nil {
		slog.Warning(commLogMsg.InvalidInputBadParam)
		log.Error("resource/certificates:GetCertificates() Query parameter certType is in invalid format")
		httpWriter.Write([]byte("Query parameter certType is in invalid format"))
		httpWriter.WriteHeader(http.StatusBadRequest)
		return
	}

	responseBodyBytes, err := ioutil.ReadAll(httpRequest.Body)
	if err != nil {
		slog.Warning(commLogMsg.InvalidInputBadParam)
		log.WithError(err).Error("resource/certificates:GetCertificates() Could not read http request body")
		httpWriter.Write([]byte("Cannot read http request body"))
		httpWriter.WriteHeader(http.StatusBadRequest)
		return
	}

	pemBlock, _ := pem.Decode(responseBodyBytes)
	if pemBlock == nil || !strings.Contains (pemBlock.Type, "CERTIFICATE REQUEST") {
		slog.Warning(commLogMsg.InvalidInputBadEncoding)
		log.WithError(err).Error("resource/certificates:GetCertificates() Failed to decode pem block containing certificate")
		httpWriter.WriteHeader(http.StatusBadRequest) 
		httpWriter.Write([]byte("Failed to decode pem" + err.Error()))
		return
	}

	clientCSR, err := x509.ParseCertificateRequest(pemBlock.Bytes)
	if err != nil {
		slog.Warning(commLogMsg.InvalidInputBadParam)
		log.WithError(err).Error("resource/certificates:GetCertificates() Invalid CSR provided")
		httpWriter.WriteHeader(http.StatusBadRequest)
		httpWriter.Write([]byte("Invalid CSR provided: " + err.Error()))
		return
	}
	err = clientCSR.CheckSignature()
	if err != nil {
		slog.Warning(commLogMsg.InvalidInputBadParam)
		log.WithError(err).Error("resource/certificates:GetCertificates() CSR signature does not match")
		httpWriter.WriteHeader(http.StatusBadRequest)
		httpWriter.Write([]byte("Invalid CSR provided: " + err.Error()))
		return
	}

	err = validation.ValidateCertificateRequest(config, clientCSR, certType, ctxMap)
	if err != nil {
		slog.Warning(commLogMsg.InvalidInputBadParam)
		log.WithError(err).Error("resource/certificates:GetCertificates() Invalid CSR provided")
		log.Tracef("%+v",err)
		httpWriter.WriteHeader(http.StatusBadRequest)
		httpWriter.Write([]byte("Invalid CSR provided: " + err.Error()))
		return
	}
	log.Debug("resource/certificates:GetCertificates() Received valid CSR")
	
	serialNumber, err := utils.GetNextSerialNumber()
	if err != nil {
		log.WithError(err).Error("resource/certificates:GetCertificates() Failed to read next Serial Number")
		log.Tracef("%+v",err)
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
		Subject:      pkix.Name{
			CommonName: clientCSR.Subject.CommonName,
		},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
	}

	// TODO: is the certificate requested is not a TLS certificate, we need to make sure that there is no SAN list
	// in the CSR and that the the CN is not in the form of a domain name/ IP address

	var issuingCa string
	log.Debugf("resource/certificates:GetCertificates() Processing CSR with cert type - %v", certType)
	if strings.EqualFold(certType, "TLS") {
		issuingCa = constants.Tls
		clientCRTTemplate.DNSNames =  clientCSR.DNSNames
		clientCRTTemplate.IPAddresses = clientCSR.IPAddresses

		clientCRTTemplate.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment
		clientCRTTemplate.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
	} else if strings.EqualFold(certType, "Flavor-Signing") || strings.EqualFold(certType, "JWT-Signing") || strings.EqualFold(certType, "Signing") {
		issuingCa = constants.Signing
		clientCRTTemplate.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment
	} else if strings.EqualFold(certType, "TLS-Client") {
		issuingCa = constants.TlsClient
		clientCRTTemplate.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment
		clientCRTTemplate.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	
	} else {
		log.Errorf("Invalid certType provided")
		httpWriter.WriteHeader(http.StatusBadRequest)
		httpWriter.Write([]byte("Invalid certType provided"))
		return
	}
	caAttr := constants.GetCaAttribs(issuingCa)

	caCert, caPrivKey, err := crypt.LoadX509CertAndPrivateKey(caAttr.CertPath, caAttr.KeyPath)
	if err != nil {
		log.WithError(err).Error("resource/certificates:GetCertificates() Could not load Issuing CA")
		log.Tracef("%+v",err)
		httpWriter.WriteHeader(http.StatusInternalServerError)
		httpWriter.Write([]byte("Cannot load Issuing CA"))
	}

	certificate, err := x509.CreateCertificate(rand.Reader, &clientCRTTemplate, caCert, clientCSR.PublicKey, caPrivKey)
	if err != nil {
		log.WithError(err).Error("resource/certificates:GetCertificates() Cannot create certificate from CSR")
		log.Tracef("%+v",err)
		httpWriter.WriteHeader(http.StatusInternalServerError)
		httpWriter.Write([]byte("Cannot create certificate"))
	}
		
	httpWriter.Header().Add("Content-Type", "application/x-pem-file")
	httpWriter.WriteHeader(http.StatusOK)
	// encode the certificate first
	pem.Encode(httpWriter, &pem.Block{Type: "CERTIFICATE", Bytes: certificate})
	// include the issuing CA as well since clients would need the entire chain minus the root.
	pem.Encode(httpWriter, &pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw})
	log.Infof("resource/certificates:GetCertificates() Issued certificate for requested CSR with CN - %v", clientCSR.Subject.String())
	return
}
