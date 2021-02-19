/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package resource

import (
	"encoding/json"
	"fmt"
	"intel/isecl/shvs/v3/constants"
	"intel/isecl/shvs/v3/repository"
	"intel/isecl/shvs/v3/types"
	"net/http"
	"strconv"
)

type PlatformSgxData struct {
	EncryptedPPID string `json:"enc-ppid"`
	CPUSvn        string `json:"cpusvn"`
	PceSvn        string `json:"pcesvn"`
	PceID         string `json:"pceid"`
	QeID          string `json:"qeid"`
	Manifest      string `json:"Manifest"`
}
type SgxData struct {
	SgxSupported bool   `json:"sgx-supported"`
	SgxEnabled   bool   `json:"sgx-enabled"`
	FlcEnabled   bool   `json:"flc-enabled"`
	EpcOffset    string `json:"epc-offset"`
	EpcSize      string `json:"epc-size"`
}

type SgxAgentResponse struct {
	SgxDataValue         SgxData         `json:"sgx-data"`
	PlatformSgxDataValue PlatformSgxData `json:"sgx-platform-data"`
}

type SCSPushResponse struct {
	Status  string `json:"Status"`
	Message string `json:"Message"`
}

type SCSGetResponse struct {
	Status  string `json:"Status"`
	Message string `json:"Message"`
}

func retrieveHostAttestationReport(db repository.SHVSDatabase) errorHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {
		log.Trace("resource/sgx_atte_report_ops: retrieveHostAttestationReport() Entering")
		defer log.Trace("resource/sgx_atte_report_ops: retrieveHostAttestationReport() Leaving")

		if len(r.URL.Query()) == 0 {
			return &resourceError{Message: "retrieveHostAttestationReport: The Request Query Data not provided",
				StatusCode: http.StatusBadRequest}
		}

		ID := r.URL.Query().Get("id")
		HostID := r.URL.Query().Get("hostID")
		HostName := r.URL.Query().Get("hostName")
		HostHardwareUUID := r.URL.Query().Get("hostHardwareID")
		HostStatus := r.URL.Query().Get("hostStatus")
		LatestperHost := r.URL.Query().Get("latestPerHost")

		if ID != "" {
			if !validateInputString(constants.ID, ID) {
				return &resourceError{Message: "retrieveHostAttestationReport: Invalid query Param Data",
					StatusCode: http.StatusBadRequest}
			}
		}
		if HostID != "" {
			if !validateInputString(constants.HostID, HostID) {
				return &resourceError{Message: "retrieveHostAttestationReport: Invalid query Param Data",
					StatusCode: http.StatusBadRequest}
			}
		}
		if HostName != "" {
			if !validateInputString(constants.HostName, HostName) {
				return &resourceError{Message: "retrieveHostAttestationReport: Invalid query Param Data",
					StatusCode: http.StatusBadRequest}
			}
		}
		if HostHardwareUUID != "" {
			if !validateInputString(constants.UUID, HostHardwareUUID) {
				return &resourceError{Message: "retrieveHostAttestationReport: Invalid query Param Data",
					StatusCode: http.StatusBadRequest}
			}
		}
		if HostStatus != "" {
			if !validateInputString(constants.HostStatus, HostStatus) {
				return &resourceError{Message: "retrieveHostAttestationReport: Invalid query Param Data",
					StatusCode: http.StatusBadRequest}
			}
		}

		perHost, _ := strconv.ParseBool(LatestperHost)
		log.WithField("LatestperHost", LatestperHost).Debug("Value")

		rs := types.SgxHostReportInputData{
			ID:             ID,
			HostID:         HostID,
			HostHardwareID: HostHardwareUUID,
			HostName:       HostName,
			Status:         HostStatus,
			LatestperHost:  perHost,
		}
		log.Debug("SgxHostReportInputData:", rs)

		existingReportData, err := db.HostReportRepository().GetHostReportQuery(&rs)
		if err != nil {
			return &resourceError{Message: err.Error(), StatusCode: http.StatusInternalServerError}
		}
		log.Debug("existingReportData", existingReportData)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK) // HTTP 200
		js, err := json.Marshal(fmt.Sprintf("%s", existingReportData))
		if err != nil {
			return &resourceError{Message: err.Error(), StatusCode: http.StatusInternalServerError}
		}
		_, err = w.Write(js)
		if err != nil {
			return &resourceError{Message: err.Error(), StatusCode: http.StatusInternalServerError}
		}
		return nil
	}
}
