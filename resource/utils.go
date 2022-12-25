/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package resource

import (
	"github.com/google/uuid"
	"github.com/pkg/errors"
	"strconv"
	"sync"
	"time"

	"intel/isecl/shvs/v5/config"
	"intel/isecl/shvs/v5/repository"
	"intel/isecl/shvs/v5/types"
)

var statusUpdateLock *sync.Mutex

func UpdateHostStatus(hostID uuid.UUID, db repository.SHVSDatabase, status string) error {
	log.Trace("resource/utils: UpdateHostStatus() Entering")
	defer log.Trace("resource/utils: UpdateHostStatus() Leaving")

	if statusUpdateLock == nil {
		statusUpdateLock = new(sync.Mutex)
	}
	existingHostStatus := &types.HostStatus{
		HostID: hostID,
	}

	existingHostStatusRec, err := db.HostStatusRepository().Retrieve(existingHostStatus)
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
		ID:          existingHostStatusRec.ID,
		HostID:      hostID,
		Status:      status,
		CreatedTime: existingHostStatusRec.CreatedTime,
		UpdatedTime: time.Now(),
		ExpiryTime:  time.Now().Add(expiryTimeDuration),
	}

	err = db.HostStatusRepository().Update(&hostStatus)
	if err != nil {
		statusUpdateLock.Unlock()
		return errors.New("UpdateHostStatus: Error while caching Host Status Information: " + err.Error())
	}
	statusUpdateLock.Unlock()
	return nil
}
