/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package resource

import (
	"intel/isecl/cms/constants"
	"intel/isecl/cms/config"
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

	rootCACertificateBytes, err := ioutil.ReadFile(constants.RootCACertPath)
	if err != nil {
		log.Errorf("Cannot read from Root CA certificate file: %v", err)
		httpWriter.WriteHeader(http.StatusInternalServerError)
		httpWriter.Write([]byte("Cannot read from Root CA certificate file"))
		return
	}
	httpWriter.Header().Set("Content-Type", "application/x-pem-file")
	httpWriter.WriteHeader(http.StatusOK)
	httpWriter.Write(rootCACertificateBytes)
	return

}
