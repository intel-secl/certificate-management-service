/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package resource

import (
	"net/http"
	"github.com/gorilla/mux"
)

func setupRouter() *mux.Router {
	m := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r)
                })
	}
	r := mux.NewRouter().PathPrefix("/cms").Subrouter()
	r.Use(m)
	return r
}
