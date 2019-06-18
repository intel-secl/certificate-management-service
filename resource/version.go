/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package resource

import (
	"fmt"
	"intel/isecl/cms/version"
	"intel/isecl/cms/config"
	"net/http"

	"github.com/gorilla/mux"
)

func SetVersion(r *mux.Router, config *config.Configuration) {
	r.Handle("/version", getVersion()).Methods("GET")
}

func getVersion() http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		verStr := fmt.Sprintf("%s-%s", version.Version, version.GitHash)
		w.Write([]byte(verStr))
	})
}
