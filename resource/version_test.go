/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package resource

import (
	"net/http"
	"net/http/httptest"

	"github.com/gorilla/mux"
	consts "github.com/intel-secl/intel-secl/v5/pkg/lib/common/constants"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("VersionTest", func() {
	var router *mux.Router
	var w *httptest.ResponseRecorder

	BeforeEach(func() {
		router = mux.NewRouter()
	})

	Describe("GetVersion", func() {
		Context("GetVersion request", func() {
			It("Should GetVersion", func() {
				SetVersionRoutes(router)
				// router.Handle("/version", getVersion()).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/version", nil)

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))
			})
		})
	})
})
