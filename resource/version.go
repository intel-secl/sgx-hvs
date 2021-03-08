/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package resource

import (
	"intel/isecl/shvs/v3/constants"
	"intel/isecl/shvs/v3/version"
	"net/http"

	"github.com/gorilla/mux"
)

func SetVersionRoutes(r *mux.Router) {
	r.Handle("/version", getVersion()).Methods("GET")
}

func getVersion() http.HandlerFunc {
	log.Trace("resource/version:getVersion() Entering")
	defer log.Trace("resource/version:getVersion() Leaving")

	return func(w http.ResponseWriter, r *http.Request) {
		verStr := version.GetVersion()
		w.Header().Add(constants.HstsHeaderKey, constants.HstsHeaderValue)
		_, err := w.Write([]byte(verStr))
		if err != nil {
			log.WithError(err).Error("Could not write version to response")
		}
	}
}
