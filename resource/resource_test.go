/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package resource

import (
	"intel/isecl/lib/common/v2/middleware"
	"intel/isecl/cms/v2/config"
	"github.com/gorilla/mux"
	"time"
)

func mockRetrieveJWTSigningCerts() error {
	log.Trace("resource/resource_test:mockRetrieveJWTSigningCerts() Entering")
	defer log.Trace("resource/resource_test:mockRetrieveJWTSigningCerts() Leaving")

	return nil
}


func setupRouter() *mux.Router {
	log.Trace("resource/resource_test:setupRouter() Entering")
	defer log.Trace("resource/resource_test:setupRouter() Leaving")


	r := mux.NewRouter()
	sr := r.PathPrefix("/cms/v1/certificates").Subrouter()
	sr.Use(middleware.NewTokenAuth("test_resources", "test_resources", mockRetrieveJWTSigningCerts, time.Hour*1))
	c := config.Configuration{}
	func(setters ...func(*mux.Router, *config.Configuration)) {
		for _, s := range setters {
			s(sr, &c)
		}
	}(SetCertificates)

	sr = r.PathPrefix("/cms/v1").Subrouter()
	sr.Use(middleware.NewTokenAuth("test_resources", "test_resources", mockRetrieveJWTSigningCerts, time.Hour*1))
	func(setters ...func(*mux.Router, *config.Configuration)) {
		for _, s := range setters {
			s(sr,&c)
		}
	}(SetVersion, SetCACertificates)

	return r
}
