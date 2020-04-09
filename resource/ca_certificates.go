/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package resource

import (
	"intel/isecl/cms/v2/constants"
	"intel/isecl/cms/v2/config"
	"fmt"
	"strings"
	"net/http"
	"io/ioutil"
	"github.com/gorilla/mux"
	commLogMsg "intel/isecl/lib/common/v2/log/message"
)

// SetCACertificates is used to set the endpoints for CA certificate handling APIs
func SetCACertificates(router *mux.Router, config *config.Configuration) {
	log.Trace("resource/ca_certificates:SetCACertificates() Entering")
	defer log.Trace("resource/ca_certificates:SetCACertificates() Leaving")

	router.HandleFunc("/ca-certificates", GetCACertificates).Methods("GET")
}

//GetCACertificates is used to get the root CA certificate upon JWT valildation
func GetCACertificates(httpWriter http.ResponseWriter, httpRequest *http.Request) {
	log.Trace("resource/ca_certificates:GetCACertificates() Entering")
	defer log.Trace("resource/ca_certificates:GetCACertificates() Leaving")

	if httpRequest.Header.Get("Accept") != "application/x-pem-file" {
		httpWriter.WriteHeader(http.StatusNotAcceptable)
		httpWriter.Write([]byte("Accept type not supported"))
		return
	}

	issuingCa := httpRequest.URL.Query().Get("issuingCa")
	if (issuingCa == "") {
		issuingCa = "root"		
	}
	log.Debugf("resource/ca_certificates:GetCACertificates() Requesting CA certificate for - %v", issuingCa)
	caCertificateBytes, err := getCaCert(issuingCa)
	if err != nil {
		log.Errorf("resource/ca_certificates:GetCACertificates() Cannot load Issuing CA - %v", issuingCa)
		log.Tracef("%+v",err)
		if strings.Contains(err.Error(), "Invalid Query parameter") {
			slog.Warning(commLogMsg.InvalidInputBadParam)
			httpWriter.WriteHeader(http.StatusBadRequest)
			httpWriter.Write([]byte("Invalid Query parameter provided"))
		} else {
			httpWriter.WriteHeader(http.StatusInternalServerError)
			httpWriter.Write([]byte("Cannot load Issuing CA"))
		}
		return
	}
	httpWriter.Header().Set("Content-Type", "application/x-pem-file")
	httpWriter.WriteHeader(http.StatusOK)
	httpWriter.Write(caCertificateBytes)
	log.Infof("resource/ca_certificates:GetCACertificates() Returned requested %v CA certificate", issuingCa)
	return
}

func getCaCert(issuingCa string) ([]byte, error) {
	log.Trace("resource/ca_certificates:getCaCert() Entering")
	defer log.Trace("resource/ca_certificates:getCaCert() Leaving")

	attr := constants.GetCaAttribs(issuingCa)
	if attr.CommonName == "" {
		return nil, fmt.Errorf("Invalid Query parameter issuingCa: %v", issuingCa)
	} else {
		return ioutil.ReadFile(attr.CertPath)
	}	
}
