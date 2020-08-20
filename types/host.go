/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package types

import (
	"time"
)

// Host struct is the database schema of a Host table
type Host struct {
	Id               string    `json:"host_ID" gorm:"type:uuid;unique;primary_key;"`
	Name             string    `json:"host_name" gorm:"not null;unique"`
	Description      string    `json:"-"`
	ConnectionString string    `json:"connection_string" gorm:"not null"`
	HardwareUUID     string    `json:"uuid" gorm:"type:uuid"`
	CreatedTime      time.Time `json:"-"`
	UpdatedTime      time.Time `json:"-"`
	Deleted          bool      `json:"-" gorm:"type:bool;not null;default:false"`
}

type Hosts []Host
