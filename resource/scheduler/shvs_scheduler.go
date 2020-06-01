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

	//"intel/isecl/sgx-host-verification-service/types"
	"intel/isecl/sgx-host-verification-service/constants"
	"intel/isecl/sgx-host-verification-service/repository"
	"intel/isecl/sgx-host-verification-service/resource"
)

func StartSHVSScheduler(db repository.SHVSDatabase, timer int) {
	log.Trace("StartSHVSScheduler: started")
	defer log.Trace("StartSHVSScheduler: Leaving")
	stop := make(chan os.Signal)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		ticker := time.NewTicker(time.Second * time.Duration(timer))
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				fmt.Fprintln(os.Stderr, "StartSHVSScheduler: Got Signal for exit and exiting.... Refresh Timer")
				break
			case t := <-ticker.C:
				log.Debug("StartSHVSScheduler: Timer started", t)
				_, err := shvsSchedulerJobCB(db)
				if err != nil {
					log.WithError(err).Info("StartSHVSScheduler: HostQueueScheduler got error")
					break
				}
			}
		}
	}()
}

func shvsSchedulerJobCB(db repository.SHVSDatabase) (bool, error) {

	log.Trace("SHVSSchedulerJobCB: Job stated")
	queues := []string{constants.HostStatusSCSQueued, constants.HostStatusAgentQueued, constants.HostStatusTCBSCSStatusQueued}

	queuedHosts, err := db.HostStatusRepository().RetrieveAllQueues(queues)
	if err != nil {
		log.WithError(err).Info("SHVSSchedulerJobCB: Error in Get Host Status Repository")
		return false, errors.New("SHVSSchedulerJobCB: Error in Get Host Status Repository")
	}

	if len(queuedHosts) == 0 {
		log.Info("SHVSSchedulerJobCB: No Host in status SCS-Queued............. Nothing to do")
		return true, nil
	}

	wq := GetWorkerQueue()
	if wq == nil {
		fmt.Fprintln(os.Stderr, "SHVSSchedulerJobCB: Workqueue is nil")
		log.Error("SHVSSchedulerJobCB: Workqueue is nil")
		return false, errors.New("SHVSSchedulerJobCB: Workqueue is nil")
	}

	for i := 0; i < len(queuedHosts); i++ {
		hostData := queuedHosts[i]
		jobData := new(resource.AttReportThreadData)
		jobData.Conn = db
		jobData.Uuid = hostData.HostId

		job := new(Job)

		if hostData.Status == constants.HostStatusTCBSCSStatusQueued {
			job.FuncPtr = resource.GetLatestTCBInfoCB
		} else if hostData.Status == constants.HostStatusSCSQueued {
			job.FuncPtr = resource.PushSGXDataToCachingServiceCB
		} else if hostData.Status == constants.HostStatusAgentQueued {
			job.FuncPtr = resource.GetSGXDataFromAgentCB
		}
		job.JobFuncData = jobData
		job.UpdateJobStatus(JobStatusInit)

		wq.AddJobAndSendSignalToWorkQueue(job)
		log.Trace("SHVSSchedulerJobCB: Job ended")
	}
	return true, nil
}
