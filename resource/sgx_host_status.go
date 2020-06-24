/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package resource

import (
        "fmt"
        "intel/isecl/shvs/constants"
        "net/http"
        "encoding/json"
        "intel/isecl/shvs/repository"
)

func HostStateInformationCB (db repository.SHVSDatabase) (errorHandlerFunc) {
        return func(w http.ResponseWriter, r *http.Request) error {
                log.Trace("resource/sgx_host_status: HostStateInformationCB() Entering")
                defer log.Trace("resource/sgx_host_status: HostStateInformationCB() Leaving")

                err := AuthorizeEndpoint(r, constants.HostDataReaderGroupName, true)
                if err != nil {
                        return err
                }
	        if ( len(r.URL.Query()) == 0) {
	                return &resourceError{Message: "HostStateInformationCB: The Request Query Data not provided", StatusCode: http.StatusBadRequest}
                }

	        hostStatusData, err := db.HostStatusRepository().GetHostStateInfo()
	        if err != nil {
			log.WithError(err).Error("resource/sgx_host_status: HostStateInformationCB() Error in retrieving host state information")
	                return &resourceError{Message: err.Error(), StatusCode: http.StatusInternalServerError}
                }
                log.Debug("hostStatusData",hostStatusData)

                w.Header().Set("Content-Type", "application/json")
                w.WriteHeader(http.StatusOK) // HTTP 200
                js, err := json.Marshal(fmt.Sprintf("%s", hostStatusData))
                if err != nil {
                        return &resourceError{Message: err.Error(), StatusCode: http.StatusInternalServerError}
                }
                w.Write(js)
		return nil
	}
}
