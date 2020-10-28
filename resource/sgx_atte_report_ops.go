/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package resource

import (
	"bytes"
	"encoding/json"
	"fmt"
	uuid "github.com/google/uuid"
	"github.com/pkg/errors"
	"intel/isecl/lib/clients/v3"
	"net/http"
	"strconv"
	"time"

	"intel/isecl/shvs/v3/config"
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
		w.Write(js)
		return nil
	}
}

func fetchSGXDataFromAgent(hostId string, db repository.SHVSDatabase, AgentUrl string) (bool, error) {
	log.Trace("resource/sgx_atte_report_ops: fetchSGXDataFromAgent() Entering")
	defer log.Trace("resource/sgx_atte_report_ops: fetchSGXDataFromAgent() Leaving")

	client, err := clients.HTTPClientWithCADir(constants.TrustedCAsStoreDir)
	if err != nil {
		log.WithError(err).WithField("id", hostId).Info("Error in getting client object")
		return false, errors.Wrap(err, "fetchSGXDataFromAgent: Error in getting client object")
	}

	req, err := http.NewRequest("GET", AgentUrl, nil)
	if err != nil {
		log.WithError(err).Info("Failed to Get New request")
		return false, errors.Wrap(err, "fetchSGXDataFromAgent: Failed to Get New request")
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	conf := config.Global()
	if conf == nil {
		return false, errors.Wrap(errors.New("fetchSGXDataFromAgent: Configuration pointer is null"), "Config error")
	}

	err = addJWTToken(req)
	if err != nil {
		return false, errors.Wrap(err, "resource/sgx_atte_report_ops: fetchSGXDataFromAgent() Failed to add JWT token to the authorization header")
	}

	resp, err := client.Do(req)
	if err != nil {
		err1 := UpdateHostStatus(hostId, db, constants.HostStatusAgentRetry)
		if err1 != nil {
			return true, errors.Wrap(err1, "fetchSGXDataFromAgent: Error while caching Host Status Information: "+err.Error())
		}
		return true, errors.Wrap(err, "fetchSGXDataFromAgent: client call failed")
	}

	log.Debug("fetchSGXDataFromAgent: Status: ", resp.StatusCode)

	if resp.StatusCode == http.StatusUnauthorized {
		// fetch token and try again
		aasRWLock.Lock()
		aasClient.FetchAllTokens()
		aasRWLock.Unlock()
		err = addJWTToken(req)
		if err != nil {
			return false, errors.Wrap(err, "fetchSGXDataFromAgent: Failed to add JWT token to the authorization header")
		}
		resp, err = client.Do(req)
		if err != nil {
			return false, errors.Wrap(err, "fetchSGXDataFromAgent: Error from response")
		}
	}

	if resp.StatusCode != http.StatusOK {
		return false, errors.New("fetchSGXDataFromAgent: Invalid status code received" + strconv.Itoa(resp.StatusCode))
	}

	var agentResponse SgxAgentResponse

	dec := json.NewDecoder(resp.Body)
	dec.DisallowUnknownFields()

	err = dec.Decode(&agentResponse)
	if err != nil {
		return false, errors.Wrap(err, "fetchSGXDataFromAgent: Read Response failed")
	}

	log.Debug("fetchSGXDataFromAgent: Status: ", agentResponse)
	resp.Body.Close()

	hostData := &types.HostSgxData{
		HostId: hostId,
	}

	hostSGXData, err := db.HostSgxDataRepository().Retrieve(*hostData)

	if hostSGXData == nil || err != nil {
		log.Debug("fetchSGXDataFromAgent: No host record found will create new one")

		sgxData := types.HostSgxData{
			Id:           uuid.New().String(),
			HostId:       hostId,
			SgxSupported: agentResponse.SgxDataValue.SgxSupported,
			SgxEnabled:   agentResponse.SgxDataValue.SgxEnabled,
			FlcEnabled:   agentResponse.SgxDataValue.FlcEnabled,
			EpcAddr:      agentResponse.SgxDataValue.EpcOffset,
			EpcSize:      agentResponse.SgxDataValue.EpcSize,
			CreatedTime:  time.Now(),
		}
		_, err = db.HostSgxDataRepository().Create(sgxData)
	} else {
		log.Debug("fetchSGXDataFromAgent: Host record found will update existing one")
		sgxData := types.HostSgxData{
			Id:           hostSGXData.Id,
			HostId:       hostId,
			SgxSupported: agentResponse.SgxDataValue.SgxSupported,
			SgxEnabled:   agentResponse.SgxDataValue.SgxEnabled,
			FlcEnabled:   agentResponse.SgxDataValue.FlcEnabled,
			EpcAddr:      agentResponse.SgxDataValue.EpcOffset,
			EpcSize:      agentResponse.SgxDataValue.EpcSize,
			CreatedTime:  time.Now(),
		}
		err = db.HostSgxDataRepository().Update(sgxData)
	}
	if err != nil {
		return false, errors.Wrap(err, "fetchSGXDataFromAgent: Error in creating host sgx data")
	}

	if agentResponse.SgxDataValue.SgxSupported == true && agentResponse.SgxDataValue.SgxEnabled == true {
		platformData := &types.PlatformTcb{
			HostId: hostId,
		}

		platformSGXData, err := db.PlatformTcbRepository().Retrieve(*platformData)

		if platformSGXData == nil || err != nil {
			platformData := types.PlatformTcb{
				Id:          uuid.New().String(),
				QeId:        agentResponse.PlatformSgxDataValue.QeId,
				HostId:      hostId,
				PceId:       agentResponse.PlatformSgxDataValue.PceId,
				CpuSvn:      agentResponse.PlatformSgxDataValue.CpuSvn,
				PceSvn:      agentResponse.PlatformSgxDataValue.PceSvn,
				Encppid:     agentResponse.PlatformSgxDataValue.EncryptedPPID,
				Manifest:    agentResponse.PlatformSgxDataValue.Manifest,
				CreatedTime: time.Now(),
			}
			_, err = db.PlatformTcbRepository().Create(platformData)
		} else {
			platformData := types.PlatformTcb{
				Id:          platformSGXData.Id,
				QeId:        agentResponse.PlatformSgxDataValue.QeId,
				HostId:      hostId,
				PceId:       agentResponse.PlatformSgxDataValue.PceId,
				CpuSvn:      agentResponse.PlatformSgxDataValue.CpuSvn,
				PceSvn:      agentResponse.PlatformSgxDataValue.PceSvn,
				Encppid:     agentResponse.PlatformSgxDataValue.EncryptedPPID,
				Manifest:    agentResponse.PlatformSgxDataValue.Manifest,
				CreatedTime: time.Now(),
			}
			err = db.PlatformTcbRepository().Update(platformData)
		}
		if err != nil {
			return false, errors.Wrap(err, "fetchSGXDataFromAgent: Error in creating platform tcb data")
		}
		return true, nil
	} else {
		err = UpdateHostStatus(hostId, db, constants.HostStatusConnected)
		if err != nil {
			return true, errors.New("fetchSGXDataFromAgent: Error while caching Host Status Information: " + err.Error())
		}
		return false, nil
	}
}

func fetchLatestTCBInfoFromSCS(db repository.SHVSDatabase, platformData *types.PlatformTcb) (bool, error) {

	client, err := clients.HTTPClientWithCADir(constants.TrustedCAsStoreDir)
	if err != nil {
		return false, errors.Wrap(err, "fetchLatestTCBInfoFromSCS : Error in getting client object")
	}

	conf := config.Global()
	if conf == nil {
		return false, errors.Wrap(errors.New("fetchLatestTCBInfoFromSCS: Configuration pointer is null"), "Config error")
	}

	getTcbInfoUrl := conf.ScsBaseUrl + "platforminfo/tcbstatus?qeid=" + platformData.QeId

	req, err := http.NewRequest("GET", getTcbInfoUrl, nil)
	if err != nil {
		return false, errors.Wrap(err, "fetchLatestTCBInfoFromSCS: Failed to Get New request")
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	err = addJWTToken(req)
	if err != nil {
		return false, errors.Wrap(err, "resource/sgx_atte_report_ops: fetchLatestTCBInfoFromSCS() Failed to add JWT token to the authorization header")
	}

	resp, err := client.Do(req)
	if err != nil {
		err1 := UpdateHostStatus(platformData.HostId, db, constants.HostStatusTCBSCSRetry)
		if err1 != nil {
			return true, errors.Wrap(err, "fetchLatestTCBInfoFromSCS: Error while updating Host Status Information: "+err.Error())
		}
		return true, errors.Wrap(err, "fetchLatestTCBInfoFromSCS: client call failed. Retrying")
	}

	log.Debug("fetchLatestTCBInfoFromSCS: Status: ", resp.StatusCode)

	if resp.StatusCode == http.StatusUnauthorized {
		// fetch token and try again
		aasRWLock.Lock()
		aasClient.FetchAllTokens()
		aasRWLock.Unlock()
		err = addJWTToken(req)
		if err != nil {
			return false, errors.Wrap(err, "fetchLatestTCBInfoFromSCS: Failed to add JWT token to the authorization header")
		}
		resp, err = client.Do(req)
		if err != nil {
			return false, errors.Wrap(err, "fetchLatestTCBInfoFromSCS: Error from response")
		}
	}

	if resp.StatusCode != http.StatusOK {
		return false, errors.New("fetchLatestTCBInfoFromSCS: Invalid status code received: " + strconv.Itoa(resp.StatusCode))
	}

	var scsResponse SCSGetResponse
	dec := json.NewDecoder(resp.Body)
	dec.DisallowUnknownFields()

	err = dec.Decode(&scsResponse)
	if err != nil {
		return false, errors.Wrap(err, "fetchLatestTCBInfoFromSCS: Read Response failed")
	}

	log.Debug("fetchLatestTCBInfoFromSCS: Status: ", scsResponse)
	resp.Body.Close()

	///Update the data in database
	///Get existing data
	host_sgx_data := &types.HostSgxData{
		HostId: platformData.HostId,
	}

	existingHostData, err := db.HostSgxDataRepository().Retrieve(*host_sgx_data)
	if existingHostData == nil || err != nil {
		log.WithError(err).WithField("id", platformData.HostId).Info("attempt to retrieve invalid host")
		return false, errors.New("fetchLatestTCBInfoFromSCS: Error in getting HostSgxData")
	}

	status, _ := strconv.ParseBool(scsResponse.Status)

	tcbUpToDate := types.HostSgxData{
		Id:           existingHostData.Id,
		HostId:       existingHostData.HostId,
		SgxSupported: existingHostData.SgxSupported,
		SgxEnabled:   existingHostData.SgxEnabled,
		FlcEnabled:   existingHostData.FlcEnabled,
		EpcAddr:      existingHostData.EpcAddr,
		EpcSize:      existingHostData.EpcSize,
		CreatedTime:  existingHostData.CreatedTime,
		TcbUptodate:  status,
	}

	err = db.HostSgxDataRepository().Update(tcbUpToDate)
	if err != nil {
		return false, errors.Wrap(err, "fetchLatestTCBInfoFromSCS: Error in updating tcbUpToDate sgx data")
	}
	return true, nil
}

func pushSGXData(db repository.SHVSDatabase, platformData *types.PlatformTcb) (bool, error) {
	log.Trace("resource/sgx_atte_report_ops: pushSGXData() Entering")
	defer log.Trace("resource/sgx_atte_report_ops: pushSGXData() Leaving")
	client, err := clients.HTTPClientWithCADir(constants.TrustedCAsStoreDir)
	if err != nil {
		return false, errors.Wrap(err, "pushSGXData: Error in getting client object")
	}

	conf := config.Global()
	if conf == nil {
		return false, errors.Wrap(errors.New("pushSGXData: Configuration pointer is null"), "Config error")
	}

	pushUrl := conf.ScsBaseUrl + "platforminfo/push"

	requestStr := map[string]string{
		"enc_ppid": platformData.Encppid,
		"cpu_svn":  platformData.CpuSvn,
		"pce_svn":  platformData.PceSvn,
		"pce_id":   platformData.PceId,
		"qe_id":    platformData.QeId,
		"manifest": platformData.Manifest}

	reqBytes, err := json.Marshal(requestStr)
	if err != nil {
		return false, errors.Wrap(err, "pushSGXData: Marshal error:"+err.Error())
	}

	req, err := http.NewRequest("POST", pushUrl, bytes.NewBuffer(reqBytes))
	if err != nil {
		return false, errors.Wrap(err, "pushSGXData: Failed to Get New request")
	}

	req.Header.Set("Content-Type", "application/json")
	err = addJWTToken(req)
	if err != nil {
		return false, errors.Wrap(err, "resource/sgx_atte_report_ops: pushSGXData() Failed to add JWT token to the authorization header")
	}

	resp, err := client.Do(req)
	if err != nil {
		err1 := UpdateHostStatus(platformData.HostId, db, constants.HostStatusSCSRetry)
		if err1 != nil {
			return true, errors.Wrap(err, "pushSGXData: Error while caching Host Status Information: "+err.Error())
		}
		return true, errors.Wrap(err, "pushSGXData: client call failed")
	}

	log.Debug("pushSGXData: Status: ", resp.StatusCode)

	if resp.StatusCode == http.StatusUnauthorized {
		// fetch token and try again
		aasRWLock.Lock()
		aasClient.FetchAllTokens()
		aasRWLock.Unlock()
		err = addJWTToken(req)
		if err != nil {
			return false, errors.Wrap(err, "pushSGXData: Failed to add JWT token to the authorization header")
		}
		resp, err = client.Do(req)
		if err != nil {
			return false, errors.Wrap(err, "pushSGXData: Error from response")
		}
	}

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return false, errors.New("pushSGXData: Invalid status code received: " + strconv.Itoa(resp.StatusCode))
	}

	log.Info("resp.StatusCode: ", resp.StatusCode)
	var pushResponse SCSPushResponse

	dec := json.NewDecoder(resp.Body)
	dec.DisallowUnknownFields()

	err = dec.Decode(&pushResponse)
	if err != nil {
		return false, errors.Wrap(err, "pushSGXData: Read Response failed")
	}

	log.Debug("pushSGXData: Status: ", pushResponse)
	resp.Body.Close()
	return true, nil
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

func PushSGXDataToCachingServiceCB(workerId int, jobData interface{}) error {
	log.Trace("resource/sgx_atte_report_ops: PushSGXDataToCachingServiceCB() Entering")
	defer log.Trace("resource/sgx_atte_report_ops: PushSGXDataToCachingServiceCB() Leaving")

	if workerId < 0 || jobData == nil {
		return errors.New("PushSGXDataToCachingServiceCB: Invalid inputs provided")
	}

	jobDataCasted := jobData.(*AttReportThreadData)
	db := jobDataCasted.Conn
	hostId := jobDataCasted.Uuid

	log.Debug("PushSGXDataToCachingServiceCB: HostId:", hostId)

	if db == nil || len(hostId) == 0 {
		return errors.New("PushSGXDataToCachingServiceCB: Invalid inputs provided  db or hostId is null")
	}

	err := UpdateHostStatus(hostId, db, constants.HostStatusSCSProcessing)
	if err != nil {
		return errors.New("PushSGXDataToCachingServiceCB: Error while Updating Host Status Information: " + err.Error())
	}

	host := &types.PlatformTcb{
		HostId: hostId,
	}

	hostPlatformData, err := db.PlatformTcbRepository().Retrieve(*host)
	if err != nil {
		log.Error("PushSGXDataToCachingServiceCB: Error in getting host platform record")
		err := UpdateHostStatus(hostId, db, constants.HostStatusProcessError)
		if err != nil {
			return errors.New("PushSGXDataToCachingServiceCB: Error while Updating Host Status Information: " + err.Error())
		}
		return errors.Wrap(err, "PushSGXDataToCachingServiceCB: Error in getting host record")
	}

	if hostPlatformData == nil {
		log.Error("PushSGXDataToCachingServiceCB: No host record found")
		err := UpdateHostStatus(hostId, db, constants.HostStatusProcessError)
		if err != nil {
			return errors.New("PushSGXDataToCachingServiceCB: Error while Updating Host Status Information: " + err.Error())
		}
		return errors.Wrap(errors.New("PushSGXDataToCachingServiceCB:"), "Error in getting host record")
	}

	flag, err := pushSGXData(db, hostPlatformData)
	if flag == false && err != nil {
		log.Error("PushSGXDataToCachingServiceCB: Error in SGX Data push: ", err.Error())
		err := UpdateHostStatus(hostId, db, constants.HostStatusProcessError)
		if err != nil {
			return errors.New("PushSGXDataToCachingServiceCB: Error while Updating Host Status Information: " + err.Error())
		}
	} else if flag == true && err != nil {
		///Status is already changed to retry.
		return errors.New("Pushing data to SCS ended with Error. Will Retry." + err.Error())

	} else if flag == true && err == nil {
		err = UpdateHostStatus(hostId, db, constants.HostStatusTCBSCSStatusQueued)
		if err != nil {
			return errors.New("PushSGXDataToCachingServiceCB: Error while Updating Host Status Information: " + err.Error())
		}
	}
	log.Debug("PushSGXDataToCachingServiceCB: Completed successfully")
	return nil
}

func GetSGXDataFromAgentCB(workerId int, jobData interface{}) error {
	log.Trace("resource/sgx_atte_report_ops: GetSGXDataFromAgentCB() Entering")
	defer log.Trace("resource/sgx_atte_report_ops: GetSGXDataFromAgentCB() Leaving")

	if workerId < 0 || jobData == nil {
		return errors.New("GetSGXDataFromAgentCB: Invalid inputs provided")
	}

	log.Debug("GetSGXDataFromAgentCB: Invoked")
	jobDataCasted := jobData.(*AttReportThreadData)
	db := jobDataCasted.Conn
	hostId := jobDataCasted.Uuid

	log.Debug("GetSGXDataFromAgentCB: HostId:", hostId)

	if db == nil || len(hostId) == 0 {
		return errors.New("GetSGXDataFromAgentCB: Invalid inputs provided  db or hostId is null")
	}

	err := UpdateHostStatus(hostId, db, constants.HostStatusAgentProcessing)
	if err != nil {
		return errors.New("GetSGXDataFromAgentCB: Error while Updating Host Status Information: " + err.Error())
	}

	host := &types.Host{
		Id: hostId,
	}

	hostData, err := db.HostRepository().Retrieve(*host)
	if err != nil {
		return errors.Wrap(err, "GetSGXDataFromAgentCB: Error in getting host record")
	}

	if hostData == nil {
		return errors.Wrap(errors.New("GetSGXDataFromAgentCB:"), "Error in getting host record")
	}

	flag, err := fetchSGXDataFromAgent(hostData.Id, db, hostData.ConnectionString)
	if flag == false && err != nil {
		log.WithError(err).Info("Fetch Sgx Data From Agent ends with Error")
		err := UpdateHostStatus(hostId, db, constants.HostStatusProcessError)
		if err != nil {
			return errors.New("GetSGXDataFromAgentCB: Error while Updating Host Status Information: " + err.Error())
		}
	} else if flag == true && err == nil {
		err = UpdateHostStatus(hostId, db, constants.HostStatusSCSQueued)
		if err != nil {
			return errors.New("GetSGXDataFromAgentCB: Error while Updating Host Status Information: " + err.Error())
		}
	} else if flag == true && err != nil {
		///Status is already changed to retry.
		return errors.New("Fetch Sgx Data From Agent ends with Error. Will Retry." + err.Error())

	}
	log.Debug("GetSGXDataFromAgentCB: Completed successfully")
	return nil
}

func GetLatestTCBInfoCB(workerId int, jobData interface{}) error {
	log.Trace("resource/sgx_atte_report_ops: GetLatestTCBInfoCB() Entering")
	defer log.Trace("resource/sgx_atte_report_ops: GetLatestTCBInfoCB() Leaving")

	if workerId < 0 || jobData == nil {
		log.Error("GetLatestTCBInfoCB: Invalid inputs provided")
		return errors.New("GetLatestTCBInfoCB: Invalid inputs provided")
	}

	jobDataCasted := jobData.(*AttReportThreadData)
	db := jobDataCasted.Conn
	hostId := jobDataCasted.Uuid

	if db == nil || len(hostId) == 0 {
		log.Error("GetLatestTCBInfoCB: Invalid inputs provided db or hostId is null")
		return errors.New("GetLatestTCBInfoCB: Invalid inputs provided  db or hostId is null")
	}
	err := UpdateHostStatus(hostId, db, constants.HostStatusSCSTCBProcessing)
	if err != nil {
		return errors.New("GetSGXDataFromAgentCB: Error while Updating Host Status Information: " + err.Error())
	}

	host := &types.PlatformTcb{
		HostId: hostId,
	}

	hostPlatformData, err := db.PlatformTcbRepository().Retrieve(*host)
	if err != nil {
		log.WithError(err).Info("GetLatestTCBInfoCB: Error in getting host platform record")
		err := UpdateHostStatus(hostId, db, constants.HostStatusProcessError)
		if err != nil {
			return errors.New("GetLatestTCBInfoCB: Error while Updating Host Status Information: " + err.Error())
		}
		return errors.Wrap(err, "GetLatestTCBInfoCB: Error in getting host record")
	}

	if hostPlatformData == nil {
		log.Error("GetLatestTCBInfoCB: No host record found")
		err := UpdateHostStatus(hostId, db, constants.HostStatusProcessError)
		if err != nil {
			return errors.New("GetLatestTCBInfoCB: Error while Updating Host Status Information: " + err.Error())
		}
		return errors.Wrap(errors.New("GetLatestTCBInfoCB:"), "Error in getting host record as it is null")
	}

	flag, err := fetchLatestTCBInfoFromSCS(db, hostPlatformData)

	if flag == false && err != nil {
		log.WithError(err).Info("GetLatestTCBInfoCB: Fetch tcbInfo From SCS ends with Error")
		err := UpdateHostStatus(hostId, db, constants.HostStatusProcessError)
		if err != nil {
			return errors.New("GetLatestTCBInfoCB: Error while Updating Host Status Information: " + err.Error())
		}
	} else if flag == true && err == nil {
		err = UpdateHostStatus(hostId, db, constants.HostStatusConnected)
		if err != nil {
			return errors.New("GetSGXDataFromAgentCB: Error while Updating Host Status Information: " + err.Error())
		}
	} else if flag == true && err != nil {
		///Status is already changed to retry.
		return errors.New("Fetch TCBInfo latest ends with Error. Will Retry." + err.Error())
	}
	return nil
}
