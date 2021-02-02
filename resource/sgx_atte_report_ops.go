/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package resource

import (
	"encoding/json"
	"fmt"
	uuid "github.com/google/uuid"
	"github.com/pkg/errors"

	"net/http"
	"strconv"
	"time"

	"intel/isecl/shvs/v3/constants"
	"intel/isecl/shvs/v3/repository"
	"intel/isecl/shvs/v3/types"
)

type PlatformSgxData struct {
	EncryptedPPID string `json:"enc-ppid"`
	CpuSvn        string `json:"cpusvn"`
	PceSvn        string `json:"pcesvn"`
	PceId         string `json:"pceid"`
	QeId          string `json:"qeid"`
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

		Id := r.URL.Query().Get("id")
		HostId := r.URL.Query().Get("hostId")
		HostName := r.URL.Query().Get("hostName")
		HostHardwareUUID := r.URL.Query().Get("hostHardwareId")
		HostStatus := r.URL.Query().Get("hostStatus")
		LatestperHost := r.URL.Query().Get("latestPerHost")

		if Id != "" {
			if !validateInputString(constants.ID, Id) {
				return &resourceError{Message: "retrieveHostAttestationReport: Invalid query Param Data",
					StatusCode: http.StatusBadRequest}
			}
		}
		if HostId != "" {
			if !validateInputString(constants.HostID, HostId) {
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
			Id:             Id,
			HostId:         HostId,
			HostHardwareId: HostHardwareUUID,
			HostName:       HostName,
			Status:         HostStatus,
			LatestperHost:  perHost,
		}
		log.Debug("SgxHostReportInputData:", rs)

		existingReportData, err := db.HostReportRepository().GetHostReportQuery(rs)
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

func createHostReport(db repository.SHVSDatabase, hostId string, status string) error {
	report := types.HostReport{
		Id:          uuid.New().String(),
		HostId:      hostId,
		TrustReport: status,
		CreatedTime: time.Now(),
	}

	_, err := db.HostReportRepository().Create(report)
	if err != nil {
		return errors.Wrap(err, "createHostReport: Error in creating Host report: "+err.Error())
	}
	return nil
}
