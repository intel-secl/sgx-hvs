/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package types

import (
	"time"
)

// Host struct is the database schema of a Host table
type Host struct {
	Id 			string     `json:"-" gorm:"type:uuid;unique;primary_key;"`
	Name       		string     `json:"-" gorm:"not null"`
	Description    		string     `json:"-"` 
	ConnectionString 	string     `json:"-" gorm:"not null"`
	HardwareUUID 		string     `json:"-" gorm:"type:uuid"`
	CreatedTime             time.Time  `json:"-"`
        UpdatedTime             time.Time  `json:"-"`
	Deleted			bool	   `json:"-" gorm:"type:bool;not null;default:false"`
}

type Hosts []Host

