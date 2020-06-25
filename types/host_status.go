/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package types

import (
	"time"
)

// HostStatus struct is the database schema of a HostStatus table
type HostStatus struct {
	Id               string    `json:"-"  gorm:"type:uuid;primary_key"`
	HostId           string    `json:"-" gorm:"type:uuid;not null"`
	Status           string    `json:"-"`
	HostReport       string    `json:"-" gorm:"not null"`
	AgentRetryCount  int       `json:"-"`
	SCSRetryCount    int       `json:"-"`
	TCBSCSRetryCount int       `json:"-"`
	CreatedTime      time.Time `json:"-"`
	UpdatedTime      time.Time `json:"-"`
	ExpiryTime       time.Time `json:"validTo"`
}

type HostsStatus []HostStatus
