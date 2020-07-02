/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package resource

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	uuid "github.com/google/uuid"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/pkg/errors"
	"intel/isecl/lib/common/v2/validation"
	"intel/isecl/shvs/constants"
	"intel/isecl/shvs/repository"
	"intel/isecl/shvs/types"
)

type ResponseJson struct {
	Id      string
	Status  string
	Message string
}

type RegisterResponse struct {
	Response   ResponseJson
	HttpStatus int
}

type RegisterHostInfo struct {
	HostId           string `json:"host_ID"`
	HostName         string `json:"host_name"`
	ConnectionString string `json:"connection_string"`
	Description      string `json:"description, omitempty"`
	UUID             string `json:"uuid"`
	Overwrite        bool   `json:"overwrite"`
}

type AttReportThreadData struct {
	Uuid string
	Conn repository.SHVSDatabase
}

func SGXHostRegisterOps(r *mux.Router, db repository.SHVSDatabase) {
	log.Trace("resource/registerhost_ops: RegisterHostOps() Entering")
	defer log.Trace("resource/registerhost_ops: RegisterHostOps() Leaving")

	r.Handle("/hosts", handlers.ContentTypeHandler(registerHost(db), "application/json")).Methods("POST")
	r.Handle("/hosts/{id}", handlers.ContentTypeHandler(getHosts(db), "application/json")).Methods("GET")
	r.Handle("/hosts", handlers.ContentTypeHandler(queryHosts(db), "application/json")).Methods("GET")
	r.Handle("/platform-data", handlers.ContentTypeHandler(getPlatformData(db), "application/json")).Methods("GET")
	r.Handle("/reports", handlers.ContentTypeHandler(retrieveHostAttestationReport(db), "application/json")).Methods("GET")
	r.Handle("/latestPerHost", handlers.ContentTypeHandler(retrieveHostAttestationReport(db), "application/json")).Methods("GET")
	r.Handle("/host-status", handlers.ContentTypeHandler(hostStateInformation(db), "application/json")).Methods("GET")
	r.Handle("/hosts/{id}", deleteHost(db)).Methods("DELETE")
}

func getHosts(db repository.SHVSDatabase) errorHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {
		log.Trace("getHosts entering")

		err := authorizeEndpoint(r, constants.HostListReaderGroupName, true)
		if err != nil {
			return err
		}

		id := mux.Vars(r)["id"]
		validation_err := validation.ValidateUUIDv4(id)
		if validation_err != nil {
			return &resourceError{Message: validation_err.Error(), StatusCode: http.StatusBadRequest}
		}

		ext_host, err := db.HostRepository().Retrieve(types.Host{Id: id})
		if ext_host == nil || err != nil {
			log.WithError(err).WithField("id", id).Info("attempt to fetch invalid host")
			return &resourceError{Message: "Host with given id don't exist",
				StatusCode: http.StatusNotFound}
		}

		host_Info := RegisterHostInfo{
			HostId:           ext_host.Id,
			HostName:         ext_host.Name,
			ConnectionString: ext_host.ConnectionString,
			UUID:             ext_host.HardwareUUID,
		}

		///Write the output here.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		js, err := json.Marshal(host_Info)
		if err != nil {
			log.WithError(err).Info("Marshalling unsuccessful")
			return &resourceError{Message: err.Error(), StatusCode: http.StatusInternalServerError}
		}
		w.Write(js)
		log.Trace("getHosts leaving")
		return nil
	}
}

func queryHosts(db repository.SHVSDatabase) errorHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {
		log.Trace("queryHosts entering")

		err := authorizeEndpoint(r, constants.HostListReaderGroupName, true)
		if err != nil {
			return err
		}

		hardwareUUID := r.URL.Query().Get("HardwareUUID")
		hostName := r.URL.Query().Get("HostName")

		if hostName != "" {
			if !validateInputString(constants.HostName, hostName) {
				return &resourceError{Message: "queryHosts: Invalid query Param Data",
					StatusCode: http.StatusBadRequest}
			}
		}

		if hardwareUUID != "" {
			if !validateInputString(constants.UUID, hardwareUUID) {
				return &resourceError{Message: "queryHosts: Invalid query Param Data",
					StatusCode: http.StatusBadRequest}
			}
		}

		filter := types.Host{
			HardwareUUID: hardwareUUID,
			Name:         hostName,
		}

		hostData, err := db.HostRepository().GetHostQuery(&filter)

		if err != nil {
			log.WithError(err).WithField("filter", filter).Info("failed to retrieve roles")
			return &resourceError{Message: err.Error(), StatusCode: http.StatusInternalServerError}
		}
		if len(hostData) == 0 {
			log.Error("no data is found")
			return &resourceError{Message: "no host is found", StatusCode: http.StatusOK}
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK) // HTTP 200
		js, err := json.Marshal(hostData)
		if err != nil {
			return &resourceError{Message: err.Error(), StatusCode: http.StatusInternalServerError}
		}
		w.Write(js)
		log.Trace("queryHosts leaving")
		return nil
	}
}

func getPlatformData(db repository.SHVSDatabase) errorHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {
		log.Trace("getPlatformData entering")

		err := authorizeEndpoint(r, constants.HostDataReaderGroupName, true)
		if err != nil {
			return err
		}

		var platformData types.HostsSgxData
		response := make([]map[string]interface{}, 0)
		hostName := r.URL.Query().Get("HostName")
		if hostName != "" {
			if !validateInputString(constants.HostName, hostName) {
				return &resourceError{Message: "getPlatformData: Invalid query Param Data",
					StatusCode: http.StatusBadRequest}
			}
			rs := types.Host{Name: hostName}
			///Get hosts data with the given hostname
			hostData, err := db.HostRepository().Retrieve(rs)
			if err != nil {
				log.WithError(err).WithField("HostName", hostName).Info("failed to retrieve hosts")
				return &resourceError{Message: err.Error(), StatusCode: http.StatusInternalServerError}
			}
			rs1 := types.HostSgxData{HostId: hostData.Id}
			platformData, err = db.HostSgxDataRepository().RetrieveAll(rs1)
			if err != nil {
				log.WithError(err).WithField("HostName", hostName).Info("failed to retrieve host data")
				return &resourceError{Message: err.Error(), StatusCode: http.StatusInternalServerError}
			}

			hostStatus := types.HostStatus{HostId: hostData.Id}
			nonExpiredHosts, err := db.HostStatusRepository().RetrieveNonExpiredHost(hostStatus)
			if err != nil {
				log.WithError(err).WithField("HostName", hostName).Info("failed to retrieve host status")
				return &resourceError{Message: err.Error(), StatusCode: http.StatusInternalServerError}
			}
			expiryTimeInString := (nonExpiredHosts.ExpiryTime).Format(time.RFC3339)

			for _, platformDataForOneHost := range platformData {
				marshalledData, err := json.Marshal(platformDataForOneHost)
				if err != nil {
					log.Error("Error marshalling the platform data")
					continue
				}
				var newPlatformData map[string]interface{}
				err = json.Unmarshal(marshalledData, &newPlatformData)
				if err != nil {
					log.Error("Error unmarshalling the platform data")
					continue
				}
				newPlatformData[constants.ExpiryTimeKeyName] = expiryTimeInString
				response = append(response, newPlatformData)
			}
		} else {
			numberOfMinutes := r.URL.Query().Get("numberOfMinutes")
			if numberOfMinutes != "" {
				_, err := strconv.Atoi(numberOfMinutes)
				if err != nil {
					log.WithError(err).Info("error came in converting numberOfMinutes from string to integer")
					return &resourceError{Message: "getPlatformData : Invalid query Param Data",
						StatusCode: http.StatusBadRequest}
				}
			}
			///Get all the hosts from host_statuses who are updated recently and status="CONNECTED"
			m, _ := time.ParseDuration(numberOfMinutes + "m")
			updatedTime := time.Now().Add(time.Duration((-m)))

			var err error
			platformData, err = db.HostSgxDataRepository().GetPlatformData(updatedTime)
			if err != nil {
				log.WithError(err).WithField("numberOfMinutes", updatedTime).Info("failed to retrieve updated hosts")
				return &resourceError{Message: err.Error(), StatusCode: http.StatusInternalServerError}
			}
			for _, platformDataForOneHost := range platformData {
				hostStatus := types.HostStatus{HostId: platformDataForOneHost.HostId}
				nonExpiredHosts, err := db.HostStatusRepository().RetrieveNonExpiredHost(hostStatus)
				if err != nil {
					log.WithError(err).WithField("numberOfMinutes", platformDataForOneHost.HostId).Info("failed to retrieve host status")
					continue
				}
				expiryTimeInString := (nonExpiredHosts.ExpiryTime).Format(time.RFC3339)
				marshalledData, err := json.Marshal(platformDataForOneHost)
				if err != nil {
					log.Error("Error marshalling the platform data")
					continue
				}
				var newPlatformData map[string]interface{}
				err = json.Unmarshal(marshalledData, &newPlatformData)
				if err != nil {
					log.Error("Error unmarshalling the platform data")
					continue
				}
				newPlatformData[constants.ExpiryTimeKeyName] = expiryTimeInString
				response = append(response, newPlatformData)
			}
		}
		log.Debug("platformData: ", platformData)
		if len(platformData) == 0 {
			log.Info("getPlatformDataCB: no platform data has been updated")
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK) // HTTP 200
		js, err := json.Marshal(response)
		if err != nil {
			return &resourceError{Message: err.Error(), StatusCode: http.StatusInternalServerError}
		}
		w.Write(js)
		log.Trace("getPlatformDataCB leaving")
		return nil
	}
}

func deleteHost(db repository.SHVSDatabase) errorHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {

		err := authorizeEndpoint(r, constants.HostListManagerGroupName, true)
		if err != nil {
			return err
		}

		id := mux.Vars(r)["id"]
		validation_err := validation.ValidateUUIDv4(id)
		if validation_err != nil {
			return &resourceError{Message: validation_err.Error(), StatusCode: http.StatusBadRequest}
		}

		ext_host, err := db.HostRepository().Retrieve(types.Host{Id: id})
		if ext_host == nil || err != nil {
			log.WithError(err).WithField("id", id).Info("attempt to delete invalid host")
			w.WriteHeader(http.StatusNoContent)
			return nil
		}

		host := types.Host{
			Id:               ext_host.Id,
			Name:             ext_host.Name,
			Description:      ext_host.Description,
			ConnectionString: ext_host.ConnectionString,
			HardwareUUID:     ext_host.HardwareUUID,
			CreatedTime:      ext_host.CreatedTime,
			UpdatedTime:      time.Now(),
			Deleted:          true,
		}
		err = db.HostRepository().Update(host)
		if err != nil {
			return errors.New("deleteHost: Error while Updating Host Information: " + err.Error())
		}
		slog.WithField("user", ext_host).Info("User deleted by:", r.RemoteAddr)
		err = UpdateHostStatus(ext_host.Id, db, constants.HostStatusRemoved)
		if err != nil {
			return errors.New("deleteHost: Error while Updating Host Status Information: " + err.Error())
		}
		w.WriteHeader(http.StatusNoContent)
		return nil
	}
}

func updateSGXHostInfo(db repository.SHVSDatabase, existingHostData *types.Host, hostInfo RegisterHostInfo) error {
	log.Trace("updateSGXHostInfo: caching sgx data:", hostInfo)

	host := types.Host{
		Id:               existingHostData.Id,
		Name:             hostInfo.HostName,
		Description:      hostInfo.Description,
		ConnectionString: hostInfo.ConnectionString,
		HardwareUUID:     hostInfo.UUID,
		CreatedTime:      existingHostData.CreatedTime,
		UpdatedTime:      time.Now(),

		Deleted: false,
	}
	err := db.HostRepository().Update(host)
	if err != nil {
		return errors.New("updateSGXHostInfo: Error while Updating Host Information: " + err.Error())
	}

	err = UpdateHostStatus(existingHostData.Id, db, constants.HostStatusAgentQueued)
	if err != nil {
		log.WithError(err).Info("updateSGXHostInfo failed")
		return errors.New("updateSGXHostInfo: Error while Updating Host Status Information: " + err.Error())
	}
	log.Trace("updateSGXHostInfo: Update SGX Host Data")
	return nil
}

func createSGXHostInfo(db repository.SHVSDatabase, hostInfo RegisterHostInfo) (string, error) {
	log.Trace("CreateSGXHostInfo: caching sgx data:", hostInfo)

	hostId := uuid.New().String()
	host := types.Host{
		Id:               hostId,
		Name:             hostInfo.HostName,
		Description:      hostInfo.Description,
		ConnectionString: hostInfo.ConnectionString,
		HardwareUUID:     hostInfo.UUID,
		CreatedTime:      time.Now(),
		UpdatedTime:      time.Now(),
	}
	_, err := db.HostRepository().Create(host)
	if err != nil {
		return "", errors.New("createSGXHostInfo: Error while caching Host Information: " + err.Error())
	}

	hostStatus := types.HostStatus{
		Id:          uuid.New().String(),
		HostId:      hostId,
		Status:      constants.HostStatusAgentQueued,
		CreatedTime: time.Now(),
		UpdatedTime: time.Now(),
	}

	_, err = db.HostStatusRepository().Create(hostStatus)
	if err != nil {
		return "", errors.New("createSGXHostInfo: Error while caching Host Status Information: " + err.Error())
	}

	log.Trace("createSGXHostInfo: Insert SGX Host Data")
	return hostId, nil
}

func sendHostRegisterResponse(w http.ResponseWriter, res RegisterResponse) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(res.HttpStatus)

	js, err := json.Marshal(res.Response)
	if err != nil {
		return errors.New("SendHostRegisterResponse: " + err.Error())
	}
	w.Write(js)
	return nil
}

func registerHost(db repository.SHVSDatabase) errorHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {

		err := authorizeEndpoint(r, constants.RegisterHostGroupName, true)
		if err != nil {
			return err
		}

		var res RegisterResponse
		var data RegisterHostInfo
		if r.ContentLength == 0 {
			res = RegisterResponse{HttpStatus: http.StatusBadRequest,
				Response: ResponseJson{Status: "Failed",
					Message: "registerHost: No request data"}}
			return sendHostRegisterResponse(w, res)
		}

		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		err = dec.Decode(&data)
		if err != nil {
			res = RegisterResponse{HttpStatus: http.StatusBadRequest,
				Response: ResponseJson{Status: "Failed",
					Message: "registerHost: Invalid Json Post Data"}}
			return sendHostRegisterResponse(w, res)
		}

		log.Debug("Calling registerHost.................", data)

		if !validateInputString(constants.HostName, data.HostName) ||
			!validateInputString(constants.ConnectionString, data.ConnectionString) ||
			!validateInputString(constants.UUID, data.UUID) ||
			!validateInputString(constants.Description, data.Description) {

			res = RegisterResponse{HttpStatus: http.StatusBadRequest,
				Response: ResponseJson{Status: "Failed",
					Message: "registerHost: Invalid query Param Data"}}
			return sendHostRegisterResponse(w, res)
		}

		host := &types.Host{
			HardwareUUID: data.UUID,
		}

		existingHostData, err := db.HostRepository().Retrieve(*host)
		if existingHostData != nil && data.Overwrite == false {
			res = RegisterResponse{HttpStatus: http.StatusOK,
				Response: ResponseJson{Status: "Success",
					Id:      existingHostData.Id,
					Message: "Host already registerd in SGX HVS"}}
			return sendHostRegisterResponse(w, res)
		} else if existingHostData != nil && data.Overwrite == true {
			err = updateSGXHostInfo(db, existingHostData, data)
			if err != nil {
				res = RegisterResponse{HttpStatus: http.StatusInternalServerError,
					Response: ResponseJson{Status: "Failed",
						Message: "registerHost: " + err.Error()}}
				return sendHostRegisterResponse(w, res)
			}

			res = RegisterResponse{HttpStatus: http.StatusCreated,
				Response: ResponseJson{Status: "Created",
					Id:      existingHostData.Id,
					Message: "SGX Host Re-registered Successfully"}}
			return sendHostRegisterResponse(w, res)

		} else if existingHostData == nil { //if existingHostData == nil

			hostId, err := createSGXHostInfo(db, data)
			if err != nil {
				res = RegisterResponse{HttpStatus: http.StatusInternalServerError,
					Response: ResponseJson{Status: "Failed",
						Message: "registerHost: " + err.Error()}}
				return sendHostRegisterResponse(w, res)
			}

			res = RegisterResponse{HttpStatus: http.StatusCreated,
				Response: ResponseJson{Status: "Success",
					Id:      hostId,
					Message: "SGX Host Registered Successfully"}}
			return sendHostRegisterResponse(w, res)
		} else {

			res = RegisterResponse{HttpStatus: http.StatusInternalServerError,
				Response: ResponseJson{Status: "Failed",
					Message: "Invalid data"}}
			return sendHostRegisterResponse(w, res)
		}
	}
}
