/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package scheduler

import (
	"container/list"
	clog "intel/isecl/lib/common/v3/log"
	"sync"
)

type ThreadSafeDLL struct {
	l      *list.List
	lMutex *sync.Mutex
}

var log = clog.GetDefaultLogger()

func InitList() *ThreadSafeDLL {
	lt := new(ThreadSafeDLL)
	lt.l = list.New()
	lt.lMutex = new(sync.Mutex)
	return lt
}

func (jobList *ThreadSafeDLL) GetElementFromList() (job interface{}) {
	log.Debug("GetElementFromList: started")
	jobList.lMutex.Lock()
	e := jobList.l.Front()
	if e != nil {
		log.Debug("GetElementFromList: Found element:", e.Value)
		jobList.l.Remove(e)
		jobList.lMutex.Unlock()
		return e.Value
	} else {
		log.Trace("GetElementFromList: No element Found")
		jobList.lMutex.Unlock()
		return nil
	}
}
