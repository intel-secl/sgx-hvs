/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package resource

import (
	"github.com/pkg/errors"
	"net/http"
	"strconv"
	"sync"
	"time"

	"intel/isecl/lib/clients/v2"
	"intel/isecl/lib/clients/v2/aas"
	"intel/isecl/sgx-host-verification-service/config"
	"intel/isecl/sgx-host-verification-service/constants"
	"intel/isecl/sgx-host-verification-service/repository"
	"intel/isecl/sgx-host-verification-service/types"
)

var statusUpdateLock *sync.Mutex

var (
	c = config.Global()
	aasClient = aas.NewJWTClient(c.AuthServiceUrl)
	aasRWLock = sync.RWMutex{}
)

func init() {
	aasRWLock.Lock()
	defer aasRWLock.Unlock()
	if aasClient.HTTPClient == nil {
		c, err := clients.HTTPClientWithCADir(constants.TrustedCAsStoreDir)
		if err != nil {
			return
		}
		aasClient.HTTPClient = c
	}
}

func addJWTToken(req *http.Request) error {
	log.Trace("resource/utils:addJWTToken() Entering")
	defer log.Trace("resource/utils:addJWTToken() Leaving")

	if aasClient.BaseURL == "" {
		aasClient = aas.NewJWTClient(c.AuthServiceUrl)
		if aasClient.HTTPClient == nil {
			c, err := clients.HTTPClientWithCADir(constants.TrustedCAsStoreDir)
			if err != nil {
				return errors.Wrap(err, "resource/utils:addJWTToken() Error initializing http client")
			}
			aasClient.HTTPClient = c
		}
	}
	aasRWLock.RLock()
	jwtToken, err := aasClient.GetUserToken(c.SHVS.User)
	aasRWLock.RUnlock()
	// something wrong
	if err != nil {
		// lock aas with w lock
		aasRWLock.Lock()
		defer aasRWLock.Unlock()
		// check if other thread fix it already
		jwtToken, err = aasClient.GetUserToken(c.SHVS.User)
		// it is not fixed
		if err != nil {
			aasClient.AddUser(c.SHVS.User, c.SHVS.Password)
			err = aasClient.FetchAllTokens()
			jwtToken, err = aasClient.GetUserToken(c.SHVS.User)
			if err != nil {
				return errors.Wrap(err, "resource/utils:addJWTToken() Could not fetch token")
			}
		}
	}
	log.Debug("resource/utils:addJWTToken() successfully added jwt bearer token")
	req.Header.Set("Authorization", "Bearer "+string(jwtToken))
	return nil
}

func UpdateHostStatus(hostId string, db repository.SHVSDatabase, status string) error {

	if statusUpdateLock == nil {
		statusUpdateLock = new(sync.Mutex)
	}
	existingHostStatus := &types.HostStatus{
		HostId: hostId,
	}

	existingHostStatusRec, err := db.HostStatusRepository().Retrieve(*existingHostStatus)
	if err != nil || existingHostStatusRec == nil {
		log.Debug("trace 1: ", existingHostStatus)
		return errors.New("UpdateHostStatus: Error while caching Host Status Information: ")
	}

	statusUpdateLock.Lock()
	var hostStatus types.HostStatus
	var vstatus string

	if status == constants.HostStatusAgentRetry {

		if existingHostStatusRec.AgentRetryCount >= constants.MaxRetryConnection {
			vstatus = constants.HostStatusAgentConnFailure
		} else {
			vstatus = constants.HostStatusAgentQueued
		}
		hostStatus = types.HostStatus{
			Id:               existingHostStatusRec.Id,
			HostId:           hostId,
			Status:           vstatus,
			AgentRetryCount:  existingHostStatusRec.AgentRetryCount + 1,
			SCSRetryCount:    existingHostStatusRec.SCSRetryCount,
			TCBSCSRetryCount: existingHostStatusRec.TCBSCSRetryCount,
			CreatedTime:      existingHostStatusRec.CreatedTime,
			UpdatedTime:      time.Now(),
		}

	} else if status == constants.HostStatusSCSRetry {

		if existingHostStatusRec.SCSRetryCount >= constants.MaxRetryConnection {
			vstatus = constants.HostStatusSCSConnFailure
		} else {
			vstatus = constants.HostStatusSCSQueued
		}
		hostStatus = types.HostStatus{
			Id:               existingHostStatusRec.Id,
			HostId:           hostId,
			Status:           vstatus,
			AgentRetryCount:  existingHostStatusRec.AgentRetryCount,
			SCSRetryCount:    existingHostStatusRec.SCSRetryCount + 1,
			TCBSCSRetryCount: existingHostStatusRec.TCBSCSRetryCount,
			CreatedTime:      existingHostStatusRec.CreatedTime,
			UpdatedTime:      time.Now(),
		}

	} else if status == constants.HostStatusTCBSCSRetry {

		if existingHostStatusRec.TCBSCSRetryCount >= constants.MaxRetryConnection {
			vstatus = constants.HostStatusTCBSCSConnFailure
		} else {
			vstatus = constants.HostStatusTCBSCSStatusQueued
		}
		hostStatus = types.HostStatus{
			Id:               existingHostStatusRec.Id,
			HostId:           hostId,
			Status:           vstatus,
			AgentRetryCount:  existingHostStatusRec.AgentRetryCount,
			SCSRetryCount:    existingHostStatusRec.SCSRetryCount,
			TCBSCSRetryCount: existingHostStatusRec.TCBSCSRetryCount + 1,
			CreatedTime:      existingHostStatusRec.CreatedTime,
			UpdatedTime:      time.Now(),
		}

	} else {
		if status == constants.HostStatusConnected {

			conf := config.Global()
			if conf == nil {
				return errors.Wrap(errors.New("UpdateHostStatus: Configuration pointer is null"), "Config error")
			}

			expiryTimeInt := conf.SHVSHostInfoExpiryTime
			expiryTimeDuration, _ := time.ParseDuration(strconv.Itoa(expiryTimeInt) + "m")

			hostStatus = types.HostStatus{
				Id:               existingHostStatusRec.Id,
				HostId:           hostId,
				Status:           status,
				CreatedTime:      existingHostStatusRec.CreatedTime,
				AgentRetryCount:  0,
				SCSRetryCount:    0,
				TCBSCSRetryCount: 0,
				UpdatedTime:      time.Now(),
				ExpiryTime:       time.Now().Add(time.Duration((expiryTimeDuration))),
			}
		} else if status == constants.HostStatusAgentQueued {
			hostStatus = types.HostStatus{
				Id:               existingHostStatusRec.Id,
				HostId:           hostId,
				Status:           status,
				CreatedTime:      existingHostStatusRec.CreatedTime,
				AgentRetryCount:  existingHostStatusRec.AgentRetryCount,
				SCSRetryCount:    existingHostStatusRec.SCSRetryCount,
				TCBSCSRetryCount: existingHostStatusRec.TCBSCSRetryCount,
				UpdatedTime:      time.Now(),
			}
		} else {
			hostStatus = types.HostStatus{
				Id:               existingHostStatusRec.Id,
				HostId:           hostId,
				Status:           status,
				CreatedTime:      existingHostStatusRec.CreatedTime,
				AgentRetryCount:  existingHostStatusRec.AgentRetryCount,
				SCSRetryCount:    existingHostStatusRec.SCSRetryCount,
				TCBSCSRetryCount: existingHostStatusRec.TCBSCSRetryCount,
				UpdatedTime:      time.Now(),
			}
		}
	}

	err = db.HostStatusRepository().Update(hostStatus)
	if err != nil {
		log.Debug("trace 2")
		statusUpdateLock.Unlock()
		return errors.New("UpdateHostStatus: Error while caching Host Status Information: " + err.Error())
	}
	statusUpdateLock.Unlock()
	return nil
}