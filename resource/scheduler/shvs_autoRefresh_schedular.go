/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package scheduler

import (
	"fmt"
	"github.com/pkg/errors"
	"os"
	"os/signal"
	"syscall"
	"time"

	"intel/isecl/sgx-host-verification-service/constants"
	"intel/isecl/sgx-host-verification-service/repository"
	"intel/isecl/sgx-host-verification-service/resource"
)

func StartAutoRefreshSchedular(db repository.SHVSDatabase, timer int) {
	log.Trace("StartAutoRefreshSchedular: started")
	defer log.Trace("StartAutoRefreshSchedular: Leaving")
	stop := make(chan os.Signal)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		ticker := time.NewTicker(time.Second * time.Duration(timer))
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				fmt.Fprintln(os.Stderr, "StartAutoRefreshSchedular: Got Signal for exit and exiting.... Refresh Timer")
				break
			case t := <-ticker.C:
				log.Debug("StartAutoRefreshSchedular: Timer started", t)
				_, err := shvsAutoRefreshSchedulerJobCB(db)
				if err != nil {
					log.WithError(err).Info("StartAutoRefreshSchedular: HostQueueScheduler got error")
					break
				}
			}
		}
	}()
}

func shvsAutoRefreshSchedulerJobCB(db repository.SHVSDatabase) (bool, error) {

	log.Trace("shvsAutoRefreshSchedulerJobCB: Job stated")

	expiredHosts, err := db.HostStatusRepository().RetrieveExpiredHosts()
	if err != nil {
		log.WithError(err).Info("StartAutoRefreshSchedular: Error in Get Host Status Repository")
		return false, errors.New("StartAutoRefreshSchedular: Error in Get Host Status Repository")
	}

	if len(expiredHosts) == 0 {
		log.Debug("StartAutoRefreshSchedular: No Host is expired ............. Nothing to do")
		return true, nil
	}
	log.Debug("shvsAutoRefreshSchedulerJobCB hosts found")

	///For each expired hosts change status in host_statuses = QUEUE
	for i := 0; i < len(expiredHosts); i++ {
		hostData := expiredHosts[i]
		hostId := hostData.HostId
		log.Debug("shvsAutoRefreshSchedulerJobCB hostId: is expired.", hostId)
		err = resource.UpdateHostStatus(hostId, db, constants.HostStatusAgentQueued)
		if err != nil {
			return false, errors.New("GetSGXDataFromAgentCB: Error while Updating Host Status Information: " + err.Error())
		}
	}
	return true, nil
}
