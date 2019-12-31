/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package types
import (
        "time"
)

// PlatformTcb struct is the database schema of a PlatformTcbs table
type PlatformTcb struct {
	Id              string     `json:"-" gorm:"type:uuid;unique;primary_key;"`
	QeId 		string     `json:"-" gorm:"not null`
	HostId		string 	   `json:"-" gorm:"type:uuid;not null"`
	PceId       	string     `json:"-"`
	CpuSvn      	string     `json:"-"`
	PceSvn      	string     `json:"-"`
	Encppid     	string	   `json:"-"`   
	CreatedTime    time.Time  `json:"-"`
}

type PlatformTcbs []PlatformTcb

