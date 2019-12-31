/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package resource

import (
	"time"
	"net/http"
	"encoding/json"

	"github.com/pkg/errors"
	"github.com/gorilla/mux"
	"github.com/gorilla/handlers"
	uuid "github.com/google/uuid"

	"intel/isecl/lib/common/validation"
	"intel/isecl/sgx-host-verification-service/types"
	"intel/isecl/sgx-host-verification-service/constants"
	"intel/isecl/sgx-host-verification-service/repository"
)

type ResponseJson struct{
	Id			string
        Status          	string
        Message         	string
}

type RegisterResponse struct {
	Response 		ResponseJson
	HttpStatus 		int
}

type RegisterHostInfo struct {
	HostName		string	`json:"host_name"`
	ConnectionString	string	`json:"connection_string"`
	Description		string	`json:"description"`
	UUID			string	`json:"uuid"`
	Overwrite		bool	`json:"overwrite"`
}

type AttReportThreadData struct{
	Uuid 			string
	Conn   			repository.SHVSDatabase
}

func SGXHostRegisterOps(r *mux.Router, db repository.SHVSDatabase) {
        log.Trace("resource/registerhost_ops: RegisterHostOps() Entering")
        defer log.Trace("resource/registerhost_ops: RegisterHostOps() Leaving")

	r.Handle("/hosts", handlers.ContentTypeHandler(RegisterHostCB(db), "application/json")).Methods("POST")
	r.Handle("/reports", handlers.ContentTypeHandler(RetriveHostAttestationReportCB(db), "application/json")).Methods("GET")
	r.Handle("/latestPerHost", handlers.ContentTypeHandler(RetriveHostAttestationReportCB(db), "application/json")).Methods("GET")
	r.Handle("/host-status", handlers.ContentTypeHandler(HostStateInformationCB(db), "application/json")).Methods("GET")
	r.Handle("/hosts/{id}", DeleteHostCB(db)).Methods("DELETE")
}

func DeleteHostCB(db repository.SHVSDatabase) errorHandlerFunc {
        return func(w http.ResponseWriter, r *http.Request) error {
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

		host :=  types.Host {
				Id: ext_host.Id,
				Name: ext_host.Name,
				Description: ext_host.Description,
				ConnectionString: ext_host.ConnectionString,
				HardwareUUID: ext_host.HardwareUUID,
				CreatedTime: ext_host.CreatedTime,
				UpdatedTime: time.Now(),
				Deleted: true,
		}
		err = db.HostRepository().Update(host)
		if  err != nil{
			return errors.New("DeleteHostCB: Error while Updating Host Information: "+ err.Error())
		}
                slog.WithField("user", ext_host).Info("User deleted by:", r.RemoteAddr)
		err = UpdateHostStatus(ext_host.Id, db, constants.HostStatusRemoved)
		if  err != nil{
			return errors.New("DeleteHostCB: Error while Updating Host Status Information: "+ err.Error())
		}
                w.WriteHeader(http.StatusNoContent)
                return nil
	}
}

func UpdateSGXHostInfo(db repository.SHVSDatabase, existingHostData *types.Host, hostInfo RegisterHostInfo) error{
	log.Debug("UpdateSGXHostInfo: caching sgx data:", hostInfo)

	host :=  types.Host {
			Id: existingHostData.Id,
        	    	Name: hostInfo.HostName,
        		Description: hostInfo.Description,
        		ConnectionString: hostInfo.ConnectionString,
        		HardwareUUID: hostInfo.UUID,
			CreatedTime: existingHostData.CreatedTime,
			UpdatedTime: time.Now(),
			Deleted: false,
	}
        err := db.HostRepository().Update(host)
        if  err != nil{
                return errors.New("UpdateSGXHostInfo: Error while Updating Host Information: "+ err.Error())
        }

	err = UpdateHostStatus(existingHostData.Id, db, constants.HostStatusAgentQueued)
        if  err != nil{
                return errors.New("UpdateSGXHostInfo: Error while Updating Host Status Information: "+ err.Error())
        }
	log.Debug("UpdateSGXHostInfo: Insert SGX Host Data")
	return nil
}

func CreateSGXHostInfo(db repository.SHVSDatabase, hostInfo RegisterHostInfo) (string, error){
	log.Debug("CreateSGXHostInfo: caching sgx data:", hostInfo)

	hostId := uuid.New().String()
	host :=  types.Host {
		Id: hostId,
        	Name: hostInfo.HostName,
        	Description: hostInfo.Description,
        	ConnectionString: hostInfo.ConnectionString,
        	HardwareUUID: hostInfo.UUID,
		CreatedTime: time.Now(),
		UpdatedTime: time.Now(),
	}
        _, err := db.HostRepository().Create(host)
        if  err != nil{
                return "", errors.New("CreateSGXHostInfo: Error while caching Host Information: "+ err.Error())
        }

	hostStatus :=  types.HostStatus {
		Id: uuid.New().String(),
		HostId: hostId,
		Status: constants.HostStatusAgentQueued,
		CreatedTime: time.Now(),
		UpdatedTime: time.Now(),
	}

        _, err = db.HostStatusRepository().Create(hostStatus)
        if  err != nil{
                return "", errors.New("CreateSGXHostInfo: Error while caching Host Status Information: "+ err.Error())
        }

	log.Debug("CreateSGXHostInfo: Insert SGX Host Data")
	return hostId, nil
}

func SendHostRegisterResponse(w http.ResponseWriter, res RegisterResponse) error {
	 w.Header().Set("Content-Type", "application/json")
         w.WriteHeader(res.HttpStatus) 

         js, err := json.Marshal(res.Response)
         if err != nil {
                        return errors.New("SendHostRegisterResponse: "+err.Error())
         }
         w.Write(js)
	 return nil
}

func RegisterHostCB(db repository.SHVSDatabase) errorHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {

		var res RegisterResponse
                var data RegisterHostInfo
                if (r.ContentLength == 0) {
			res = RegisterResponse{ HttpStatus: http.StatusBadRequest, 
					 	Response: ResponseJson{Status:"Failed", 
						Message: "RegisterHostCB: No request data"}}
			return SendHostRegisterResponse(w,  res)
                }

                dec := json.NewDecoder(r.Body)
                dec.DisallowUnknownFields()
                err := dec.Decode(&data)
                if err != nil {
			res = RegisterResponse{ HttpStatus: http.StatusBadRequest, 
					 	Response: ResponseJson{Status:"Failed", 
						Message: "RegisterHostCB: Invalid Json Post Data"}}
			return SendHostRegisterResponse(w,  res)
                }

		log.Debug("Calling RegisterHostCB.................", data)

                if       !ValidateInputString(constants.HostName, data.HostName) ||
                         !ValidateInputString(constants.ConnectionString, data.ConnectionString) ||
                         !ValidateInputString(constants.UUID, data.UUID)  {

			res = RegisterResponse{ HttpStatus: http.StatusBadRequest, 
					 	Response: ResponseJson{Status:"Failed", 
						Message: "RegisterHostCB: Invalid query Param Data"}}
			return SendHostRegisterResponse(w,  res)
                }

                host := &types.Host{
        		 HardwareUUID: data.UUID,
                }

                existingHostData, err := db.HostRepository().Retrieve(*host)
                if  existingHostData != nil  && data.Overwrite == false {
			res = RegisterResponse{ HttpStatus: http.StatusOK, 
						 Response: ResponseJson{ Status:"Success", 
						 			 Id: existingHostData.Id,
									 Message: "Host already registerd in SGX HVS"}}
			return SendHostRegisterResponse(w,  res)
                }else if  existingHostData != nil  && data.Overwrite == true {
			err = UpdateSGXHostInfo(db, existingHostData, data);
			if err != nil {
				res = RegisterResponse{ HttpStatus: http.StatusInternalServerError, 
							Response: ResponseJson{Status:"Failed", 
							Message: "RegisterHostCB: "+err.Error()}}
				return SendHostRegisterResponse(w,  res)
			}
			
			res = RegisterResponse{ HttpStatus: http.StatusCreated, 
							Response: ResponseJson{Status:"Created", 
							Id: existingHostData.Id,
							Message: "SGX Host Re-registered Successfully"}}
			return SendHostRegisterResponse(w,  res)

		}else if existingHostData == nil { //if existingHostData == nil 

			hostId, err := CreateSGXHostInfo(db, data);
			if err != nil {
				res = RegisterResponse{ HttpStatus: http.StatusInternalServerError, 
							Response: ResponseJson{Status:"Failed", 
							Message: "RegisterHostCB: "+err.Error()}}
				return SendHostRegisterResponse(w,  res)
			}
			
			res = RegisterResponse{ HttpStatus: http.StatusCreated, 
							Response: ResponseJson{Status:"Success", 
							Id: hostId,
							Message: "SGX Host Registered Successfully"}}
			return SendHostRegisterResponse(w,  res)
		}else {

			res = RegisterResponse{ HttpStatus: http.StatusInternalServerError, 
							Response: ResponseJson{Status:"Failed", 
							Message: "Invalid data"}}
			return SendHostRegisterResponse(w,  res)
		}
	}
}
