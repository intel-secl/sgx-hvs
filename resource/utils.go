/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package resource

import (
	"github.com/pkg/errors"
	"net/http"
	"strconv"
	"sync"
	"time"

	"intel/isecl/lib/clients/v3"
	"intel/isecl/lib/clients/v3/aas"
	"intel/isecl/shvs/v3/config"
	"intel/isecl/shvs/v3/constants"
	"intel/isecl/shvs/v3/repository"
	"intel/isecl/shvs/v3/types"
)

var statusUpdateLock *sync.Mutex

var (
	c         = config.Global()
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
			if err != nil {
				return errors.Wrap(err, "resource/utils:addJWTToken() FetchAllTokens Could not fetch token")
			}
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
	log.Trace("resource/utils: UpdateHostStatus() Entering")
	defer log.Trace("resource/utils: UpdateHostStatus() Leaving")

	if statusUpdateLock == nil {
		statusUpdateLock = new(sync.Mutex)
	}
	existingHostStatus := &types.HostStatus{
		HostId: hostId,
	}

	existingHostStatusRec, err := db.HostStatusRepository().Retrieve(*existingHostStatus)
	if err != nil || existingHostStatusRec == nil {
		log.WithError(err).WithField("hostStatus", existingHostStatus).Info("Error while caching Host Status Information")
		return errors.New("UpdateHostStatus: Error while caching Host Status Information: ")
	}

	statusUpdateLock.Lock()
	var hostStatus types.HostStatus

	conf := config.Global()
	if conf == nil {
		return errors.Wrap(errors.New("UpdateHostStatus: Configuration pointer is null"), "Config error")
	}

	expiryTimeInt := conf.SHVSHostInfoExpiryTime
	expiryTimeDuration, _ := time.ParseDuration(strconv.Itoa(expiryTimeInt) + "m")

	hostStatus = types.HostStatus{
		Id:          existingHostStatusRec.Id,
		HostId:      hostId,
		Status:      status,
		CreatedTime: existingHostStatusRec.CreatedTime,
		UpdatedTime: time.Now(),
		ExpiryTime:  time.Now().Add(time.Duration((expiryTimeDuration))),
	}

	err = db.HostStatusRepository().Update(hostStatus)
	if err != nil {
		statusUpdateLock.Unlock()
		return errors.New("UpdateHostStatus: Error while caching Host Status Information: " + err.Error())
	}
	statusUpdateLock.Unlock()
	return nil
}
