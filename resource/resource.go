/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package resource

import (
	"fmt"
	"intel/isecl/lib/common/v2/auth"
	"intel/isecl/lib/common/v2/context"
	"intel/isecl/sgx-host-verification-service/constants"
	"net/http"

	"github.com/jinzhu/gorm"
	clog "intel/isecl/lib/common/v2/log"
	commLogMsg "intel/isecl/lib/common/v2/log/message"
	ct "intel/isecl/lib/common/v2/types/aas"
)

var log = clog.GetDefaultLogger()
var slog = clog.GetSecurityLogger()

type errorHandlerFunc func(w http.ResponseWriter, r *http.Request) error

func (ehf errorHandlerFunc) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Trace("resource/resource:ServeHTTP() Entering")
	defer log.Trace("resource/resource:ServeHTTP() Leaving")

	if err := ehf(w, r); err != nil {
		log.WithError(err).Error("HTTP Error")
		if gorm.IsRecordNotFoundError(err) {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		switch t := err.(type) {
		case *resourceError:
			http.Error(w, t.Message, t.StatusCode)
		case resourceError:
			http.Error(w, t.Message, t.StatusCode)
		case *privilegeError:
			http.Error(w, t.Message, t.StatusCode)
		case privilegeError:
			http.Error(w, t.Message, t.StatusCode)
		default:
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
}

type privilegeError struct {
	StatusCode int
	Message    string
}

func (e privilegeError) Error() string {
	log.Trace("resource/resource:Error() Entering")
	defer log.Trace("resource/resource:Error() Leaving")

	return fmt.Sprintf("%d: %s", e.StatusCode, e.Message)
}

type resourceError struct {
	StatusCode int
	Message    string
}

func (e resourceError) Error() string {
	log.Trace("resource/resource:Error() Entering")
	defer log.Trace("resource/resource:Error() Leaving")

	return fmt.Sprintf("%d: %s", e.StatusCode, e.Message)
}

func AuthorizeEndpoint(r *http.Request, roleName string, retNilCtxForEmptyCtx bool) error {
	log.Trace("resource/resource:AuthorizeEndpoint() Entering")
	defer log.Trace("resource/resource:AuthorizeEndpoint() Leaving")

	privileges, err := context.GetUserRoles(r)
	if err != nil {
		slog.WithError(err).Error("resource/resource: AuthorizeEndpoint() Failed to read roles and permissions")
		return &resourceError{Message: "Could not get user roles from http context", StatusCode: http.StatusInternalServerError}
	}

	_, foundRole := auth.ValidatePermissionAndGetRoleContext(privileges, []ct.RoleInfo{ct.RoleInfo{Service: constants.ServiceName, Name: roleName}}, retNilCtxForEmptyCtx)
	if !foundRole {
		slog.Infof("resource/resource: AuthorizeEndpoint() %s: endpoint access unauthorized, request role: %v", commLogMsg.UnauthorizedAccess, roleName)
		return &privilegeError{Message: "", StatusCode: http.StatusForbidden}
	}
	slog.Infof("resource/resource: AuthorizeEndpoint() %s - %s", commLogMsg.AuthorizedAccess, r.RequestURI)
	return nil
}
