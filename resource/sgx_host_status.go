/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package resource

import (
	"encoding/json"
	"github.com/google/uuid"
	commLogMsg "intel/isecl/lib/common/v4/log/message"
	"intel/isecl/shvs/v4/constants"
	"intel/isecl/shvs/v4/repository"
	"intel/isecl/shvs/v4/types"
	"net/http"
	"strings"
)

type HostStatusResponse struct {
	HostID uuid.UUID `json:"host_id"`
	Status string    `json:"host_status"`
}

var hostStatusRetrieveParams = map[string]bool{"hostId": true}

func getHostStateInformation(db repository.SHVSDatabase) errorHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {
		log.Trace("resource/sgx_host_status: getHostStateInformation() Entering")
		defer log.Trace("resource/sgx_host_status: getHostStateInformation() Leaving")

		err := authorizeEndpoint(r, constants.HostDataReaderGroupName, true)
		if err != nil {
			return err
		}
		if len(r.URL.Query()) == 0 {
			return &resourceError{Message: "getHostStateInformation: The Request Query Data not provided", StatusCode: http.StatusBadRequest}
		}

		if err = validateQueryParams(r.URL.Query(), hostStatusRetrieveParams); err != nil {
			slog.WithError(err).Errorf("resource/sgx_host_status: getHostStateInformation() %s", commLogMsg.InvalidInputBadParam)
			return &resourceError{Message: err.Error(), StatusCode: http.StatusBadRequest}
		}

		var hostID uuid.UUID
		if r.URL.Query().Get("hostId") != "" {
			hostID, err = uuid.Parse(r.URL.Query().Get("hostId"))
			if err != nil {
				return &resourceError{Message: "Invalid host Id provided", StatusCode: http.StatusBadRequest}
			}
		}

		filter := &types.HostStatus{
			HostID: hostID,
		}
		hostStatusData, err := db.HostStatusRepository().Retrieve(filter)
		if err != nil {
			log.WithError(err).Error("resource/sgx_host_status: getHostStateInformation() Error in retrieving host state information")
			if strings.Contains(err.Error(), "record not found") {
				return &resourceError{Message: "Status of host with given id does not exist", StatusCode: http.StatusBadRequest}
			}
			return &resourceError{Message: err.Error(), StatusCode: http.StatusInternalServerError}
		}
		log.Debug("hostStatusData", hostStatusData)

		var hostStatuses []HostStatusResponse
		hostStatuses = append(hostStatuses, HostStatusResponse{
			HostID: hostStatusData.HostID,
			Status: hostStatusData.Status,
		})

		w.Header().Set("Content-Type", "application/json")
		w.Header().Add(constants.HstsHeaderKey, constants.HstsHeaderValue)
		w.WriteHeader(http.StatusOK) // HTTP 200

		js, err := json.Marshal(hostStatuses)
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
