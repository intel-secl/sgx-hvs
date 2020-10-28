/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package resource

import (
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"intel/isecl/lib/common/v3/middleware"
	"intel/isecl/shvs/v3/constants"
	"intel/isecl/shvs/v3/repository"
	"net/http/httptest"
	"testing"
	"time"
)

type TestData struct {
	Description string
	Recorder    *httptest.ResponseRecorder
	Assert      *assert.Assertions
	Router      *mux.Router
	Test        *testing.T
	Token       string
	Url         string
	StatusCode  int
	PostData    []byte
}

func mockRetrieveJWTSigningCerts() error {
	log.Trace("resource/resource_test:mockRetrieveJWTSigningCerts() Entering")
	defer log.Trace("resource/resource_test:mockRetrieveJWTSigningCerts() Leaving")

	return nil
}

func setupRouter(t *testing.T) *mux.Router {
	log.Trace("resource/resource_test:setupRouter() Entering")
	defer log.Trace("resource/resource_test:setupRouter() Leaving")

	r := mux.NewRouter()
	sr := r.PathPrefix("/scs/sgx/certification/v1/").Subrouter()
	func(setters ...func(*mux.Router, repository.SHVSDatabase)) {
		for _, s := range setters {
			s(sr, nil)
		}
	}(QuoteProviderOps)

	sr = r.PathPrefix("/scs/sgx/test/platforminfo/").Subrouter()
	sr.Use(middleware.NewTokenAuth("test_resources", "test_resources", mockRetrieveJWTSigningCerts, time.Minute*constants.DefaultJwtValidateCacheKeyMins))
	func(setters ...func(*mux.Router, repository.SHVSDatabase)) {
		for _, s := range setters {
			s(sr, nil)
		}
	}(PlatformInfoOps)

	sr = r.PathPrefix("/scs/sgx/test-noauth/platforminfo/").Subrouter()
	func(setters ...func(*mux.Router, repository.SHVSDatabase)) {
		for _, s := range setters {
			s(sr, nil)
		}
	}(PlatformInfoOps)
	return r
}
