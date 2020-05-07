/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package scheduler

import (
	"errors"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

type JobFunc func(int, interface{}) error

const (
	WorkerStatusInit  = 0
	WorkerStatusFree  = 1
	WorkerStatusBusy  = 2
	WorkerStatusError = 3
	WorkerStatusDied  = 4
)

const (
	JobStatusInit       = 0
	JobStatusQueued     = 1
	JobStatusCompleted  = 2
	JobStatusError      = 3
	JobStatusEmptyQueue = 4
	JobStatusProcessing = 5
)

type Job struct {
	JobFuncData interface{}
	FuncPtr     JobFunc
	Status      int
}

type Worker struct {
	wId     int
	wStatus int
	wMutex  *sync.Mutex
	wJob    *Job
}

type WorkerQueue struct {
	wCount       int
	workers      []Worker
	wList        *ThreadSafeDLL
	wQCond       *sync.Cond
	wQMutex      *sync.Mutex
	shutDownFlag bool
}

var wq *WorkerQueue

const (
	WorkerCount = 5
)

func (wq *WorkerQueue) GetJobFromWQList() *Job {
	log.Debug("GetJobFromWQList: Get job from list")
	if wq.wList == nil {
		log.Error("GetJobFromWQList: WorkQueue list is empty")
		return nil
	}
	i := wq.wList.GetElementFromList()
	if i == nil {
		log.Error("GetJobFromWQList: Invalid job got from workqueue")
		return nil
	}
	job := i.(*Job)

	log.Debug("GetJobFromWQList: Got job from Queue:", job)
	return job
}

func WorkerCB(id int, wq *WorkerQueue) {
	for {
		worker := wq.workers[id]
		wq.wQCond.L.Lock()
		worker.UpdateWorkerJob(nil)
		worker.UpdateWorkerStatus(WorkerStatusFree)
		log.Debug("Worker: ", id, " Waiting for signal.....")
		wq.wQCond.Wait()
		log.Debug("Worker: ", id, " got signal")

		if wq.GetShutDownFlag() {
			log.Trace("WorkerCB: Got shutdown signal")
			worker.UpdateWorkerStatus(WorkerStatusDied)
			wq.wQCond.L.Unlock()
			break
		}

		if worker.GetWorkerStatus() != WorkerStatusFree {
			log.Trace("WorkerCB: Worker is currently busy")
			wq.wQCond.L.Unlock()
			continue
		}

		log.Debug("Worker: ", id, " Get job from WorkQuelist")
		job := wq.GetJobFromWQList()
		if job == nil {
			log.Debug("Worker: ", id, " get invalid job or Queue is empty")
			log.Debug("Worker: ", id, " Completed the Job.....")
			wq.wQCond.L.Unlock()
			continue

		}
		wq.wQCond.L.Unlock()
		log.Debug("Worker: ", id, " Got job and go it will do the job now")

		job.UpdateJobStatus(JobStatusProcessing)
		worker.UpdateWorkerJob(job)
		worker.UpdateWorkerStatus(WorkerStatusBusy)

		if job.FuncPtr == nil {
			log.Error("Worker: ", id, " Job Function pointer is nil")
			continue
		}
		err := job.FuncPtr(id, job.JobFuncData)
		if err != nil {
			job.UpdateJobStatus(JobStatusError)
			log.Debug("Worker: ", id, " Job function ends with error")
			log.Error("Job Ends with Error: ", err.Error())

		} else {
			job.UpdateJobStatus(JobStatusCompleted)
		}
		log.Debug("Worker: ", id, " Completed the Job.....")
		worker.UpdateWorkerStatus(WorkerStatusFree)
	}
}

func GetWorkerQueue() *WorkerQueue {
	if wq == nil {
		log.Error("GetWorkerQueue: Workqueue not created")
		return nil
	}
	return wq
}
func (w *Worker) UpdateWorkerJob(job *Job) {
	w.wJob = job
}

func (w *Worker) GetWorkerStatus() int {
	return w.wStatus
}
func (w *Worker) UpdateWorkerStatus(status int) {
	w.wMutex.Lock()
	w.wStatus = status
	w.wMutex.Unlock()
}
func InitWorkerQueue() *WorkerQueue {
	if wq == nil {
		log.Debug("GetWorkerQueue: Workque created")
		wq = new(WorkerQueue)
		wq.wList = InitList()
		wq.wCount = WorkerCount
		wq.wQMutex = new(sync.Mutex)
		wq.wQCond = &sync.Cond{L: wq.wQMutex}
		wq.SetShutDownFlag(false)
		wq.workers = make([]Worker, wq.wCount)

		for i := 0; i < wq.wCount; i++ {
			worker := &wq.workers[i]
			worker.wId = i + 1
			worker.wMutex = new(sync.Mutex)
			worker.UpdateWorkerStatus(WorkerStatusInit)
		}

		for id := 0; id < wq.wCount; id++ {
			go WorkerCB(id, wq)
		}
	} else {
		log.Trace("InitWorkerQueue: Workqueue init already completed")
		return nil
	}
	return wq
}

func (wq *WorkerQueue) AddJobAndSendSignalToWorkQueue(job *Job) (error, int) {
	if job == nil {
		return errors.New("AddJobInWorkQueue: Job ptr is null"), JobStatusError
	}

	wq.wQCond.L.Lock()
	job.UpdateJobStatus(JobStatusQueued)
	wq.wList.AddElementToList(job)
	wq.wQCond.Signal()
	wq.wQCond.L.Unlock()
	return nil, JobStatusQueued
}

func (wq *WorkerQueue) AddJobInWorkQueue(job *Job) (error, int) {

	wq.wQCond.L.Lock()
	job.UpdateJobStatus(JobStatusQueued)
	wq.wList.AddElementToList(job)
	wq.wQCond.L.Unlock()
	return nil, JobStatusQueued
}

func (wq *WorkerQueue) SendSignalToWorkQueuew() {
	wq.wQCond.L.Lock()
	wq.wQCond.Signal()
	wq.wQCond.L.Unlock()
}

func (wq *WorkerQueue) SetShutDownFlag(flag bool) {
	wq.shutDownFlag = flag
}

func (wq *WorkerQueue) GetShutDownFlag() bool {
	return wq.shutDownFlag
}
func (wq *WorkerQueue) ShutdownSignalToWorkQueue() {
	wq.wQCond.L.Lock()
	wq.SetShutDownFlag(true)
	wq.wQCond.Broadcast()
	wq.wQCond.L.Unlock()
}

func (j *Job) UpdateJobStatus(status int) {
	j.Status = status
}

func StartWorkqueueScheduler(timerSec int) error {
	log.Trace("StartWorkqueueScheduler: started")
	defer log.Trace("StartWorkqueueScheduler Leaving")

	wq := InitWorkerQueue()
	stop := make(chan os.Signal)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		ticker := time.NewTicker(time.Second * time.Duration(timerSec))
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				fmt.Fprintln(os.Stderr, "StartWorkqueueScheduler: Got Signal for exit and exiting.... Refresh Timer")
				wq.ShutdownSignalToWorkQueue()
				break
			case t := <-ticker.C:
				log.Debug("StartWorkqueueScheduler: Timer started", t)
				wq.SendSignalToWorkQueuew()
			}
		}
	}()
	return nil
}
