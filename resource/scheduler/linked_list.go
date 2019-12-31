/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package scheduler

import (
	"sync"
	"container/list"
	clog "intel/isecl/lib/common/log"
)

type ThreadSafeDLL struct {
	l *list.List
	lMutex *sync.Mutex
}

var log = clog.GetDefaultLogger()
var slog = clog.GetSecurityLogger()



func InitList() *ThreadSafeDLL{
	lt := new(ThreadSafeDLL)
	lt.l = list.New()
	lt.lMutex = new(sync.Mutex)
	return lt
}

func (list *ThreadSafeDLL) AddElementToList(job interface{}){
	list.lMutex.Lock()
	list.l.PushBack(job)
    	list.lMutex.Unlock()
}

func (list *ThreadSafeDLL) GetElementFromList()(job interface{}){
	log.Debug("GetElementFromList: started")
	list.lMutex.Lock()
	e := list.l.Front()
	if e != nil {
		log.Debug("GetElementFromList: Found element:", e.Value)
		list.l.Remove(e)
    		list.lMutex.Unlock()
		return e.Value
	}else {
		log.Info("GetElementFromList: No element Found")
    		list.lMutex.Unlock()
		return nil
	}
}

func (list *ThreadSafeDLL) ListElements(){
	for e := list.l.Front(); e != nil; e = e.Next() {
		log.Debug("Printing Element in the list", e.Value)
	}
}
