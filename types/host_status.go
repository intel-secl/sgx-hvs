/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package types

import (
	"time"
)

// HostStatus struct is the database schema of a HostStatus table
type HostStatus struct {
	Id          string    `json:"-"  gorm:"type:uuid;primary_key"`
	HostId      string    `json:"-" gorm:"type:uuid;not null"`
	Status      string    `json:"-"`
	HostReport  string    `json:"-" gorm:"not null"`
	CreatedTime time.Time `json:"-"`
	UpdatedTime time.Time `json:"-"`
	ExpiryTime  time.Time `json:"validTo"`
}

type HostsStatus []HostStatus
