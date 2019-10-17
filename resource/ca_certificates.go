/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package resource

import (
	"intel/isecl/cms/constants"
	"intel/isecl/cms/config"
	"fmt"
	"strings"
	"net/http"
	"io/ioutil"
	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
)

// SetCACertificates is used to set the endpoints for CA certificate handling APIs
func SetCACertificates(router *mux.Router, config *config.Configuration) {
	router.HandleFunc("/ca-certificates", GetCACertificates).Methods("GET")
}

//GetCACertificates is used to get the root CA certificate upon JWT valildation
func GetCACertificates(httpWriter http.ResponseWriter, httpRequest *http.Request) {
	if httpRequest.Header.Get("Accept") != "application/x-pem-file" {
		httpWriter.WriteHeader(http.StatusNotAcceptable)
		httpWriter.Write([]byte("Accept type not supported"))
		return
	}

	issuingCa := httpRequest.URL.Query().Get("issuingCa")
	caCertificateBytes, err := getCaCert(issuingCa)
	if err != nil {
		log.Errorf("Cannot load Issuing CA: %v", err)
		if strings.Contains(err.Error(), "Invalid Query parameter") {
			httpWriter.WriteHeader(http.StatusBadRequest)
			httpWriter.Write([]byte("Invalid Query parameter issuing CA: "+ issuingCa))
		} else {
			httpWriter.WriteHeader(http.StatusInternalServerError)
			httpWriter.Write([]byte("Cannot load Issuing CA"))
		}
		return
	}
	httpWriter.Header().Set("Content-Type", "application/x-pem-file")
	httpWriter.WriteHeader(http.StatusOK)
	httpWriter.Write(caCertificateBytes)
	return
}

func getCaCert(issuingCa string) ([]byte, error) {
	if (issuingCa == "") {
		return ioutil.ReadFile(constants.RootCACertPath)
	} else {
		attr := constants.GetCaAttribs(issuingCa)
		if attr.CommonName == "" {
			return nil, fmt.Errorf("Invalid Query parameter issuingCa: %s", issuingCa)
		} else {
			return ioutil.ReadFile(attr.CertPath)
		}
	}
}
