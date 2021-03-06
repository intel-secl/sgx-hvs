/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package resource

import (
	"encoding/json"
	commLogMsg "intel/isecl/lib/common/v3/log/message"
	"intel/isecl/shvs/v3/constants"
	"intel/isecl/shvs/v3/repository"
	"net/http"
)

type HostStatusResponse struct {
	HostID string `json:"host_id"`
	Status string `json:"host_status"`
}

func hostStateInformation(db repository.SHVSDatabase) errorHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {
		log.Trace("resource/sgx_host_status: hostStateInformation() Entering")
		defer log.Trace("resource/sgx_host_status: hostStateInformation() Leaving")

		err := authorizeEndpoint(r, constants.HostDataReaderGroupName, true)
		if err != nil {
			return err
		}
		if len(r.URL.Query()) == 0 {
			return &resourceError{Message: "hostStateInformation: The Request Query Data not provided", StatusCode: http.StatusBadRequest}
		}

		hostStatusData, err := db.HostStatusRepository().GetHostStateInfo()
		if err != nil {
			log.WithError(err).Error("resource/sgx_host_status: hostStateInformation() Error in retrieving host state information")
			return &resourceError{Message: err.Error(), StatusCode: http.StatusInternalServerError}
		}
		log.Debug("hostStatusData", hostStatusData)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK) // HTTP 200

		hostStatusResponses := make([]HostStatusResponse, 0)
		for _, hostStatus := range *hostStatusData {
			hostStatusResponse := HostStatusResponse{
				HostID: hostStatus.HostID,
				Status: hostStatus.Status,
			}
			hostStatusResponses = append(hostStatusResponses, hostStatusResponse)
		}
		js, err := json.Marshal(hostStatusResponses)
		if err != nil {
			return &resourceError{Message: err.Error(), StatusCode: http.StatusInternalServerError}
		}
		_, err = w.Write(js)
		if err != nil {
			return &resourceError{Message: err.Error(), StatusCode: http.StatusInternalServerError}
		}
		slog.Infof("%s: Host status retrieved by: %s", commLogMsg.AuthorizedAccess, r.RemoteAddr)
		return nil
	}
}
