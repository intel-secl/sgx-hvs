/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package types
import (
	"time"
)

// HostSgxData struct is the database schema of a HostSgxData table
type HostSgxData struct {
	Id 			string     `json:"-" gorm:"primary_key;"`
	HostId       		string     `json:"-" gorm:"type:uuid;not null"`
	SgxSupported		bool	    `json:"-"`
	SgxEnabled    		bool        `json:"-"` 
	FlcEnabled    		bool        `json:"-"` 
	EpcAddr    		string     `json:"-"` 
	EpcSize    		string     `json:"-"` 
	CreatedTime    		time.Time  `json:"-"`
}
type HostsSgxData []HostSgxData

