/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package resource

import (
	"sync"
        "time"
	"net/http"
        "crypto/tls"
        "crypto/x509"
        "github.com/pkg/errors"

	cos "intel/isecl/lib/common/os"
        "intel/isecl/sgx-host-verification-service/types"
        "intel/isecl/sgx-host-verification-service/constants"
        "intel/isecl/sgx-host-verification-service/repository"
)

var statusUpdateLock *sync.Mutex
func UpdateHostStatus(hostId string, db repository.SHVSDatabase, status string) (error) {

	if statusUpdateLock == nil {
		statusUpdateLock = new(sync.Mutex)
	}
        existingHostStatus :=  &types.HostStatus {
                        HostId: hostId,
        }

        existingHostStatusRec, err := db.HostStatusRepository().Retrieve(*existingHostStatus)
        if  err != nil || existingHostStatusRec == nil {
                return errors.New("UpdateHostStatus: Error while caching Host Status Information: ")
        }

	statusUpdateLock.Lock()
	var hostStatus types.HostStatus
	var vstatus string

	if status == constants.HostStatusAgentRetry {

		if existingHostStatusRec.AgentRetryCount >= constants.MaxRetryConnection {
			vstatus = constants.HostStatusAgentConnFailure
		}else {
			vstatus = constants.HostStatusAgentQueued
		}
		hostStatus =  types.HostStatus {
				Id: existingHostStatusRec.Id,
				HostId: hostId,
				Status: vstatus,
				AgentRetryCount: existingHostStatusRec.AgentRetryCount +1,
				SCSRetryCount: existingHostStatusRec.SCSRetryCount,
				CreatedTime: existingHostStatusRec.CreatedTime,
				UpdatedTime: time.Now(),
		}

	}else if status == constants.HostStatusSCSRetry {  

		if existingHostStatusRec.SCSRetryCount >= constants.MaxRetryConnection {
			vstatus = constants.HostStatusSCSConnFailure
		}else {
			vstatus = constants.HostStatusSCSQueued
		}
		hostStatus =  types.HostStatus {
				Id: existingHostStatusRec.Id,
				HostId: hostId,
				Status: vstatus,
				AgentRetryCount: existingHostStatusRec.AgentRetryCount,
				SCSRetryCount: existingHostStatusRec.SCSRetryCount + 1,
				CreatedTime: existingHostStatusRec.CreatedTime,
				UpdatedTime: time.Now(),
		}

	}else {

		if status == constants.HostStatusConnected {
				
			hostStatus =  types.HostStatus {
					Id: existingHostStatusRec.Id,
					HostId: hostId,
					Status: status,
					CreatedTime: existingHostStatusRec.CreatedTime,
					AgentRetryCount:  0,
					SCSRetryCount: 0,
					UpdatedTime: time.Now(),
			}
		} else {

			hostStatus =  types.HostStatus {
					Id: existingHostStatusRec.Id,
					HostId: hostId,
					Status: status,
					CreatedTime: existingHostStatusRec.CreatedTime,
					AgentRetryCount:  existingHostStatusRec.AgentRetryCount,
					SCSRetryCount: existingHostStatusRec.SCSRetryCount,
					UpdatedTime: time.Now(),
			}
		}

	}
        err = db.HostStatusRepository().Update(hostStatus)
        if  err != nil{
		statusUpdateLock.Unlock()
                return errors.New("UpdateHostStatus: Error while caching Host Status Information: "+ err.Error())
        }
	statusUpdateLock.Unlock()
        return nil
}


func GetClientObj()(*http.Client, error){

        rootCaCertPems, err := cos.GetDirFileContents(constants.RootCADirPath, "*.pem" )
        if err != nil {
                return  nil, errors.Wrap(err, "GetClientObj: failed to get file contents")
        }

        // Get the SystemCertPool, continue with an empty pool on error
        rootCAs, _ := x509.SystemCertPool()
        if rootCAs == nil {
                rootCAs = x509.NewCertPool()
        }

        for _, rootCACert := range rootCaCertPems{
                if ok := rootCAs.AppendCertsFromPEM(rootCACert); !ok {
                        return  nil, errors.Wrap(err, "GetClientObj: failed to append certs from pem")
                }
        }

        client := &http.Client{
                Transport: &http.Transport{
                        TLSClientConfig: &tls.Config{
                                InsecureSkipVerify: false,
                                RootCAs: rootCAs,
                        },
                },
        }
        return client, nil
}

