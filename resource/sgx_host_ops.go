/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package resource

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/pkg/errors"
	"intel/isecl/lib/common/v3/context"
	commLogMsg "intel/isecl/lib/common/v3/log/message"
	"intel/isecl/shvs/v3/config"
	"intel/isecl/shvs/v3/constants"
	"intel/isecl/shvs/v3/repository"
	"intel/isecl/shvs/v3/types"
)

type ResponseJSON struct {
	ID      uuid.UUID
	Status  string
	Message string
}

type RegisterResponse struct {
	Response   ResponseJSON
	HTTPStatus int
}

type RegisterHostInfo struct {
	HostID      uuid.UUID `json:"host_ID"`
	HostName    string    `json:"host_name"`
	Description string    `json:"description,omitempty"`
	UUID        uuid.UUID `json:"uuid"`
}

type SGXHostInfo struct {
	HostName     string `json:"host_name"`
	Description  string `json:"description,omitempty"`
	UUID         string `json:"uuid"`
	SgxSupported bool   `json:"sgx_supported"`
	SgxEnabled   bool   `json:"sgx_enabled"`
	FlcEnabled   bool   `json:"flc_enabled"`
	EpcOffset    string `json:"epc_offset"`
	EpcSize      string `json:"epc_size"`
	TcbUptodate  bool   `json:"tcb_upToDate"`
}

type AttReportThreadData struct {
	UUID string
	Conn repository.SHVSDatabase
}

var hostsSearchParams = map[string]bool{"getPlatformData": true, "getStatus": true, "HardwareUUID": true, "HostName": true}
var hostsRetrieveParams = map[string]bool{"getPlatformData": true, "getStatus": true}

const RowsNotFound = "no rows in result set"

func SGXHostRegisterOps(r *mux.Router, db repository.SHVSDatabase) {
	log.Trace("resource/sgx_host_ops: SGXHostRegisterOps() Entering")
	defer log.Trace("resource/sgx_host_ops: SGXHostRegisterOps() Leaving")

	r.Handle("/hosts", handlers.ContentTypeHandler(registerHost(db), "application/json")).Methods("POST")
	r.Handle("/hosts/{id}", handlers.ContentTypeHandler(getHosts(db), "application/json")).Methods("GET")
	r.Handle("/hosts", handlers.ContentTypeHandler(queryHosts(db), "application/json")).Methods("GET")
	r.Handle("/platform-data", handlers.ContentTypeHandler(getPlatformData(db), "application/json")).Methods("GET")
	r.Handle("/host-status", handlers.ContentTypeHandler(getHostStateInformation(db), "application/json")).Methods("GET")
	r.Handle("/hosts/{id}", deleteHost(db)).Methods("DELETE")
}

func getHosts(db repository.SHVSDatabase) errorHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {
		log.Trace("resource/sgx_host_ops: getHosts() Entering")
		defer log.Trace("resource/sgx_host_ops: getHosts() Leaving")

		err := authorizeEndpoint(r, constants.HostListReaderGroupName, true)
		if err != nil {
			return err
		}

		id, validationErr := uuid.Parse(mux.Vars(r)["id"])
		if validationErr != nil {
			slog.Errorf("resource/sgx_host_ops: getHosts() Input validation failed for host ID")
			return &resourceError{Message: validationErr.Error(), StatusCode: http.StatusBadRequest}
		}

		if err := validateQueryParams(r.URL.Query(), hostsRetrieveParams); err != nil {
			slog.WithError(err).Errorf("resource/sgx_host_ops: getHosts() %s", commLogMsg.InvalidInputBadParam)
			return &resourceError{Message: err.Error(), StatusCode: http.StatusBadRequest}
		}

		criteria, err := populateHostInfoFetchCriteria(r.URL.Query())
		if err != nil {
			slog.WithError(err).Errorf("resource/sgx_host_ops: getHosts() %s Invalid host info fetch criteria",
				commLogMsg.InvalidInputBadParam)
			return &resourceError{Message: err.Error(), StatusCode: http.StatusBadRequest}
		}

		extHost, err := db.HostRepository().Retrieve(&types.Host{ID: id}, criteria)
		if extHost == nil || err != nil {
			log.WithError(err).WithField("id", id).Info("attempt to fetch invalid host")
			return &resourceError{Message: "Host with given id don't exist",
				StatusCode: http.StatusNotFound}
		}

		// Write the output here.
		w.Header().Set("Content-Type", "application/json")
		w.Header().Add(constants.HstsHeaderKey, constants.HstsHeaderValue)
		w.WriteHeader(http.StatusOK)
		js, err := json.Marshal(extHost)

		if err != nil {
			log.WithError(err).Info("resource/sgx_host_ops: getHosts() Marshalling unsuccessful")
			return &resourceError{Message: err.Error(), StatusCode: http.StatusInternalServerError}
		}
		_, err = w.Write(js)
		if err != nil {
			return &resourceError{Message: err.Error(), StatusCode: http.StatusInternalServerError}
		}
		slog.Infof("%s: Host retrieved by: %s", commLogMsg.AuthorizedAccess, r.RemoteAddr)
		return nil
	}
}

func queryHosts(db repository.SHVSDatabase) errorHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {
		log.Trace("resource/sgx_host_ops: queryHosts() Entering")
		defer log.Trace("resource/sgx_host_ops: queryHosts() Leaving")

		err := authorizeEndpoint(r, constants.HostListReaderGroupName, true)
		if err != nil {
			return err
		}

		if err := validateQueryParams(r.URL.Query(), hostsSearchParams); err != nil {
			slog.WithError(err).Errorf("resource/sgx_host_ops: queryHosts() %s", commLogMsg.InvalidInputBadParam)
			return &resourceError{Message: err.Error(), StatusCode: http.StatusBadRequest}
		}

		var hardwareUUID uuid.UUID
		if r.URL.Query().Get("HardwareUUID") != "" {
			hardwareUUID, err = uuid.Parse(r.URL.Query().Get("HardwareUUID"))
			if err != nil {
				return &resourceError{Message: err.Error(), StatusCode: http.StatusBadRequest}
			}
		}
		hostName := r.URL.Query().Get("HostName")

		criteria, err := populateHostInfoFetchCriteria(r.URL.Query())
		if err != nil {
			slog.WithError(err).Errorf("resource/sgx_host_ops: getHosts() %s Invalid host info fetch criteria",
				commLogMsg.InvalidInputBadParam)
			return &resourceError{Message: err.Error(), StatusCode: http.StatusBadRequest}
		}

		if hostName != "" {
			if !validateInputString(constants.HostName, hostName) {
				slog.Error("resource/sgx_host_ops: queryHosts() Input validation failed for host name query param")
				return &resourceError{Message: "queryHosts: Invalid query Param Data",
					StatusCode: http.StatusBadRequest}
			}
		}

		filter := types.Host{
			HardwareUUID: hardwareUUID,
			Name:         hostName,
		}

		hostData, err := db.HostRepository().GetHostQuery(&filter, criteria)

		if err != nil {
			log.WithError(err).WithField("filter", filter).Info("failed to retrieve hosts")
			return &resourceError{Message: err.Error(), StatusCode: http.StatusInternalServerError}
		}
		if len(hostData) == 0 {
			log.Error("resource/sgx_host_ops: queryHosts() no data is found")
			return &resourceError{Message: "no host is found", StatusCode: http.StatusNotFound}
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK) // HTTP 200
		w.Header().Add(constants.HstsHeaderKey, constants.HstsHeaderValue)
		js, err := json.Marshal(hostData)
		if err != nil {
			return &resourceError{Message: err.Error(), StatusCode: http.StatusInternalServerError}
		}
		_, err = w.Write(js)
		if err != nil {
			return &resourceError{Message: err.Error(), StatusCode: http.StatusInternalServerError}
		}
		slog.Infof("%s: Host searched by: %s", commLogMsg.AuthorizedAccess, r.RemoteAddr)
		return nil
	}
}

func getPlatformData(db repository.SHVSDatabase) errorHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {
		log.Trace("resource/sgx_host_ops: getPlatformData() Entering")
		defer log.Trace("resource/sgx_host_ops: getPlatformData() Leaving")

		err := authorizeEndpoint(r, constants.HostDataReaderGroupName, true)
		if err != nil {
			return err
		}

		var platformData *types.HostsSgxData
		response := make([]map[string]interface{}, 0)
		hostName := r.URL.Query().Get("HostName")
		if hostName != "" {
			if !validateInputString(constants.HostName, hostName) {
				slog.Errorf("resource/sgx_host_ops: getPlatformData() Input validation failed for host name")
				return &resourceError{Message: "getPlatformData: Invalid query Param Data",
					StatusCode: http.StatusBadRequest}
			}
			rs := types.Host{Name: hostName}
			// Get hosts data with the given hostname
			hostData, err := db.HostRepository().Retrieve(&rs, nil)
			if err != nil {
				log.WithError(err).WithField("HostName", hostName).Info("failed to retrieve hosts")
				return &resourceError{Message: err.Error(), StatusCode: http.StatusInternalServerError}
			}
			rs1 := types.HostSgxData{HostID: hostData.ID}
			platformData, err = db.HostSgxDataRepository().RetrieveAll(&rs1)
			if err != nil {
				log.WithError(err).WithField("HostName", hostName).Info("failed to retrieve host data")
				return &resourceError{Message: err.Error(), StatusCode: http.StatusInternalServerError}
			}

			hostStatus := types.HostStatus{HostID: hostData.ID}
			nonExpiredHosts, err := db.HostStatusRepository().RetrieveNonExpiredHost(&hostStatus)
			if err != nil {
				log.WithError(err).WithField("HostName", hostName).Info("failed to retrieve host status.")
				return &resourceError{Message: err.Error(), StatusCode: http.StatusInternalServerError}
			}

			for _, platformDataForOneHost := range *platformData {
				marshalledData, err := json.Marshal(platformDataForOneHost)
				if err != nil {
					log.Error("getPlatformData: Error marshalling the platform data")
					continue
				}
				var newPlatformData map[string]interface{}
				err = json.Unmarshal(marshalledData, &newPlatformData)
				if err != nil {
					log.Error("getPlatformData: Error unmarshalling the platform data")
					continue
				}
				newPlatformData[constants.ExpiryTimeKeyName] = nonExpiredHosts.ExpiryTime
				response = append(response, newPlatformData)
			}
		} else {
			numberOfMinutes := r.URL.Query().Get("numberOfMinutes")
			if numberOfMinutes != "" {
				_, err := strconv.Atoi(numberOfMinutes)
				if err != nil {
					log.WithError(err).Info("getPlatformData: error came in converting numberOfMinutes from string to integer")
					return &resourceError{Message: "getPlatformData: Invalid query Param Data",
						StatusCode: http.StatusBadRequest}
				}
			}
			// Get all the hosts from host_statuses which are updated recently and status="CONNECTED"
			m, _ := time.ParseDuration(numberOfMinutes + "m")
			updatedTime := time.Now().Add(-m)

			var err error
			platformData, err = db.HostSgxDataRepository().GetPlatformData(updatedTime)
			if err != nil {
				log.WithError(err).WithField("numberOfMinutes", updatedTime).Info("getPlatformData: failed to retrieve updated hosts")
				return &resourceError{Message: err.Error(), StatusCode: http.StatusInternalServerError}
			}
			for _, platformDataForOneHost := range *platformData {
				hostStatus := types.HostStatus{HostID: platformDataForOneHost.HostID}
				nonExpiredHosts, err := db.HostStatusRepository().RetrieveNonExpiredHost(&hostStatus)
				if err != nil {
					log.WithError(err).WithField("numberOfMinutes", platformDataForOneHost.HostID).Info("getPlatformData: failed to retrieve host status")
					continue
				}
				expiryTimeInString := (nonExpiredHosts.ExpiryTime).Format(time.RFC3339)
				marshalledData, err := json.Marshal(platformDataForOneHost)
				if err != nil {
					log.Error("getPlatformData: Error marshalling the platform data")
					continue
				}
				var newPlatformData map[string]interface{}
				err = json.Unmarshal(marshalledData, &newPlatformData)
				if err != nil {
					log.Error("getPlatformData: Error unmarshalling the platform data")
					continue
				}
				newPlatformData[constants.ExpiryTimeKeyName] = expiryTimeInString
				response = append(response, newPlatformData)
			}
		}
		log.Debug("platformData: ", platformData)
		if len(*platformData) == 0 {
			log.Info("getPlatformDataCB: no platform data has been updated")
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK) // HTTP 200
		w.Header().Add(constants.HstsHeaderKey, constants.HstsHeaderValue)
		js, err := json.Marshal(response)
		if err != nil {
			return &resourceError{Message: err.Error(), StatusCode: http.StatusInternalServerError}
		}
		_, err = w.Write(js)
		if err != nil {
			return &resourceError{Message: err.Error(), StatusCode: http.StatusInternalServerError}
		}
		slog.Infof("%s: Host platform data retrieved by: %s", commLogMsg.AuthorizedAccess, r.RemoteAddr)
		return nil
	}
}

func deleteHost(db repository.SHVSDatabase) errorHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {
		log.Trace("resource/sgx_host_ops: deleteHost() Entering")
		defer log.Trace("resource/sgx_host_ops: deleteHost() Leaving")

		err := authorizeEndpoint(r, constants.HostListManagerGroupName, true)
		if err != nil {
			return err
		}

		id, validationErr := uuid.Parse(mux.Vars(r)["id"])
		if validationErr != nil {
			slog.Errorf("resource/sgx_host_ops: deleteHost() Input validation failed for host Id")
			return &resourceError{Message: validationErr.Error(), StatusCode: http.StatusBadRequest}
		}

		extHost, err := db.HostRepository().Retrieve(&types.Host{ID: id}, nil)
		if extHost == nil || err != nil {
			log.WithError(err).WithField("id", id).Info("deleteHost: attempt to delete invalid host")
			w.WriteHeader(http.StatusNoContent)
			return nil
		}

		host := types.Host{
			ID:           extHost.ID,
			Name:         extHost.Name,
			Description:  extHost.Description,
			HardwareUUID: extHost.HardwareUUID,
			CreatedTime:  extHost.CreatedTime,
			UpdatedTime:  time.Now(),
			Deleted:      true,
		}
		err = db.HostRepository().Update(&host)
		if err != nil {
			return errors.New("deleteHost: Error while Updating Host Information: " + err.Error())
		}
		slog.WithField("user", extHost).Info("User deleted by:", r.RemoteAddr)
		err = UpdateHostStatus(extHost.ID, db, constants.HostStatusRemoved)
		if err != nil {
			return errors.New("deleteHost: Error while Updating Host Status Information: " + err.Error())
		}
		w.WriteHeader(http.StatusNoContent)
		w.Header().Add(constants.HstsHeaderKey, constants.HstsHeaderValue)
		return nil
	}
}

func updateSGXHostInfo(db repository.SHVSDatabase, existingHostData *types.HostInfo, hostInfo RegisterHostInfo) error {
	log.Trace("resource/sgx_host_ops: updateSGXHostInfo() Entering")
	defer log.Trace("resource/sgx_host_ops: updateSGXHostInfo() Leaving")

	host := types.Host{
		ID:           existingHostData.ID,
		Name:         hostInfo.HostName,
		Description:  hostInfo.Description,
		HardwareUUID: hostInfo.UUID,
		CreatedTime:  existingHostData.CreatedTime,
		UpdatedTime:  time.Now(),

		Deleted: false,
	}
	err := db.HostRepository().Update(&host)
	if err != nil {
		return errors.New("updateSGXHostInfo: Error while Updating Host Information: " + err.Error())
	}

	err = UpdateHostStatus(existingHostData.ID, db, constants.HostStatusConnected)
	if err != nil {
		log.WithError(err).Info("updateSGXHostInfo failed")
		return errors.New("updateSGXHostInfo: Error while Updating Host Status Information: " + err.Error())
	}
	return nil
}

func createSGXHostInfo(db repository.SHVSDatabase, hostInfo RegisterHostInfo) (uuid.UUID, error) {
	log.Trace("resource/sgx_host_ops: createSGXHostInfo() Entering")
	defer log.Trace("resource/sgx_host_ops: createSGXHostInfo() Leaving")

	hostID := uuid.New()
	host := types.Host{
		ID:           hostID,
		Name:         hostInfo.HostName,
		Description:  hostInfo.Description,
		HardwareUUID: hostInfo.UUID,
		CreatedTime:  time.Now(),
		UpdatedTime:  time.Now(),
	}
	_, err := db.HostRepository().Create(&host)
	if err != nil {
		return uuid.Nil, errors.New("createSGXHostInfo: Error while caching Host Information: " + err.Error())
	}

	conf := config.Global()
	if conf == nil {
		return uuid.Nil, errors.Wrap(errors.New("createSGXHostInfo: Configuration pointer is null"), "Config error")
	}

	expiryTimeInt := conf.SHVSHostInfoExpiryTime
	expiryTimeDuration, _ := time.ParseDuration(strconv.Itoa(expiryTimeInt) + "m")

	hostStatus := types.HostStatus{
		ID:          uuid.New(),
		HostID:      hostID,
		Status:      constants.HostStatusConnected,
		CreatedTime: time.Now(),
		UpdatedTime: time.Now(),
		ExpiryTime:  time.Now().Add(expiryTimeDuration),
	}
	_, err = db.HostStatusRepository().Create(&hostStatus)
	if err != nil {
		return uuid.Nil, errors.New("createSGXHostInfo: Error while caching Host Status Information: " + err.Error())
	}
	return hostID, nil
}

func sendHostRegisterResponse(w http.ResponseWriter, res RegisterResponse) error {
	log.Trace("resource/sgx_host_ops: sendHostRegisterResponse() Entering")
	defer log.Trace("resource/sgx_host_ops: sendHostRegisterResponse() Leaving")

	w.Header().Set("Content-Type", "application/json")
	w.Header().Add(constants.HstsHeaderKey, constants.HstsHeaderValue)
	w.WriteHeader(res.HTTPStatus)

	js, err := json.Marshal(res.Response)
	if err != nil {
		return errors.New("SendHostRegisterResponse: " + err.Error())
	}
	_, err = w.Write(js)
	if err != nil {
		return &resourceError{Message: err.Error(), StatusCode: http.StatusInternalServerError}
	}
	return nil
}

func registerHost(db repository.SHVSDatabase) errorHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {
		log.Trace("resource/sgx_host_ops: registerHost() Entering")
		defer log.Trace("resource/sgx_host_ops: registerHost() Leaving")

		err := authorizeEndpoint(r, constants.HostDataUpdaterGroupName, true)
		if err != nil {
			return err
		}

		var res RegisterResponse
		var data SGXHostInfo
		if r.ContentLength == 0 {
			slog.Error("resource/sgx_host_ops: registerHost() The request body was not provided")
			res = RegisterResponse{HTTPStatus: http.StatusBadRequest,
				Response: ResponseJSON{Status: "Failed",
					Message: "registerHost: No request data"}}
			return sendHostRegisterResponse(w, res)
		}

		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		err = dec.Decode(&data)
		if err != nil {
			slog.WithError(err).Errorf("resource/sgx_host_ops: registerHost() %s :  Failed to decode request body", commLogMsg.InvalidInputBadEncoding)
			res = RegisterResponse{HTTPStatus: http.StatusBadRequest,
				Response: ResponseJSON{Status: "Failed",
					Message: "registerHost: Invalid Json Post Data"}}
			return sendHostRegisterResponse(w, res)
		}

		log.Debug("Calling registerHost.................", data)

		hardwareUUID, err := uuid.Parse(data.UUID)

		if !validateInputString(constants.HostName, data.HostName) || err != nil ||
			!validateInputString(constants.Description, data.Description) {
			slog.Error("resource/sgx_host_ops: registerHost() Input validation failed")
			res = RegisterResponse{HTTPStatus: http.StatusBadRequest,
				Response: ResponseJSON{Status: "Failed",
					Message: "registerHost: Invalid query Param Data"}}
			return sendHostRegisterResponse(w, res)
		}

		tokenSubject, err := context.GetTokenSubject(r)
		if err != nil || tokenSubject != data.UUID {
			slog.Errorf("resource/sgx_host_ops: registerHost() %s : Failed to match host identity from token", commLogMsg.AuthenticationFailed)
			res = RegisterResponse{HTTPStatus: http.StatusUnauthorized,
				Response: ResponseJSON{Status: "Failed",
					Message: "registerHost: Invalid Token"}}
			return sendHostRegisterResponse(w, res)
		}

		host := &types.Host{
			Name: data.HostName,
		}

		hostInfo := RegisterHostInfo{
			Description: data.Description,
			HostName:    data.HostName,
			UUID:        hardwareUUID,
		}

		existingHostData, err := db.HostRepository().Retrieve(host, nil)
		if err != nil && !strings.Contains(err.Error(), RowsNotFound) {
			slog.Error("resource/sgx_host_ops: registerHost() Error retrieving data from database")
			res = RegisterResponse{HTTPStatus: http.StatusInternalServerError,
				Response: ResponseJSON{Status: "Failed",
					Message: "registerHost: Error retrieving data from database"}}
			return sendHostRegisterResponse(w, res)
		}
		if existingHostData != nil {
			if !strings.EqualFold(existingHostData.HardwareUUID.String(), tokenSubject) {
				slog.Errorf("resource/sgx_host_ops: registerHost() %s : Failed to match host identity from database", commLogMsg.AuthenticationFailed)
				res = RegisterResponse{HTTPStatus: http.StatusUnauthorized,
					Response: ResponseJSON{Status: "Failed",
						Message: "registerHost: Invalid Token"}}
				return sendHostRegisterResponse(w, res)
			}

			err = updateSGXHostInfo(db, existingHostData, hostInfo)
			if err != nil {
				res = RegisterResponse{HTTPStatus: http.StatusInternalServerError,
					Response: ResponseJSON{Status: "Failed",
						Message: "registerHost: " + err.Error()}}
				return sendHostRegisterResponse(w, res)
			}

			err = pushSGXEnablementInfoToDB(existingHostData.ID, db, &data)
			if err != nil {
				res = RegisterResponse{HTTPStatus: http.StatusInternalServerError,
					Response: ResponseJSON{Status: "Failed",
						Message: "registerHost: " + err.Error()}}
				return sendHostRegisterResponse(w, res)
			}
			res = RegisterResponse{HTTPStatus: http.StatusOK,
				Response: ResponseJSON{Status: "Success",
					ID:      existingHostData.ID,
					Message: "SGX Host Data Updated Successfully"}}
			return sendHostRegisterResponse(w, res)
		} else {
			hostID, err := createSGXHostInfo(db, hostInfo)
			if err != nil {
				res = RegisterResponse{HTTPStatus: http.StatusInternalServerError,
					Response: ResponseJSON{Status: "Failed",
						Message: "registerHost: " + err.Error()}}
				return sendHostRegisterResponse(w, res)
			}
			err = pushSGXEnablementInfoToDB(hostID, db, &data)
			if err != nil {
				res = RegisterResponse{HTTPStatus: http.StatusInternalServerError,
					Response: ResponseJSON{Status: "Failed",
						Message: "registerHost: " + err.Error()}}
				return sendHostRegisterResponse(w, res)
			}
			res = RegisterResponse{HTTPStatus: http.StatusCreated,
				Response: ResponseJSON{Status: "Success",
					ID:      hostID,
					Message: "SGX Host Data Created Successfully"}}
			return sendHostRegisterResponse(w, res)
		}
	}
}

func pushSGXEnablementInfoToDB(hostID uuid.UUID, db repository.SHVSDatabase, hostInfo *SGXHostInfo) error {
	log.Trace("resource/sgx_atte_report_ops: pushSGXEnablementInfo() Entering")
	defer log.Trace("resource/sgx_atte_report_ops: pushSGXEnablementInfo() Leaving")

	hostData := &types.HostSgxData{
		HostID: hostID,
	}

	hostSGXData, err := db.HostSgxDataRepository().Retrieve(hostData)

	if hostSGXData == nil || err != nil {
		log.Debug("resource/sgx_host_ops: No host record found will create new one")

		sgxData := types.HostSgxData{
			ID:           uuid.New(),
			HostID:       hostID,
			SgxSupported: hostInfo.SgxSupported,
			SgxEnabled:   hostInfo.SgxEnabled,
			FlcEnabled:   hostInfo.FlcEnabled,
			EpcAddr:      hostInfo.EpcOffset,
			EpcSize:      hostInfo.EpcSize,
			TcbUptodate:  hostInfo.TcbUptodate,
			CreatedTime:  time.Now(),
		}
		_, err = db.HostSgxDataRepository().Create(&sgxData)
	} else {
		log.Debug("resource/sgx_host_ops: Host record found will update existing one")
		sgxData := types.HostSgxData{
			ID:           hostSGXData.ID,
			HostID:       hostID,
			SgxSupported: hostInfo.SgxSupported,
			SgxEnabled:   hostInfo.SgxEnabled,
			FlcEnabled:   hostInfo.FlcEnabled,
			EpcAddr:      hostInfo.EpcOffset,
			EpcSize:      hostInfo.EpcSize,
			TcbUptodate:  hostInfo.TcbUptodate,
			CreatedTime:  time.Now(),
		}
		err = db.HostSgxDataRepository().Update(&sgxData)
	}
	if err != nil {
		return errors.Wrap(err, "resource/sgx_host_ops: Error in creating host sgx data")
	}
	return nil
}

func validateQueryParams(params url.Values, validQueries map[string]bool) error {
	log.Trace("resource/sgx_host_ops:validateQueryParams() Entering")
	defer log.Trace("resource/sgx_host_ops:validateQueryParams() Leaving")
	if len(params) > constants.MaxQueryParamsLength {
		return errors.New("Invalid query parameters provided. Number of query parameters exceeded maximum value")
	}
	for param := range params {
		if _, hasQuery := validQueries[param]; !hasQuery {
			return errors.New("Invalid query parameter provided. Refer to swagger doc for details.")
		}
	}
	return nil
}

func populateHostInfoFetchCriteria(params url.Values) (*types.HostInfoFetchCriteria, error) {
	log.Trace("resource/sgx_host_ops:populateHostInfoFetchCriteria() Entering")
	defer log.Trace("resource/sgx_host_ops:populateHostInfoFetchCriteria() Leaving")

	var criteria types.HostInfoFetchCriteria

	if params.Get("getPlatformData") != "" {
		getPlatformData, err := strconv.ParseBool(params.Get("getPlatformData"))
		if err != nil {
			return nil, errors.New("Invalid getPlatformData query param value, must be boolean")
		}
		criteria.GetPlatformData = getPlatformData

	}
	if params.Get("getStatus") != "" {
		getStatus, err := strconv.ParseBool(params.Get("getStatus"))
		if err != nil {
			return nil, errors.Wrap(err, "Invalid getStatus query param value, must be boolean")
		}
		criteria.GetStatus = getStatus
	}

	return &criteria, nil
}
