/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package types

import (
	"time"
)

// HostCredential struct is the database schema of a HostCredential table
type HostCredential struct {
	Id           string    `json:"-" gorm:"type:uuid;primary_key"`
	HostId       string    `json:"-" gorm:"type:uuid;not null"`
	HardwareUUID string    `json:"-" gorm:"type:uuid"`
	HostName     string    `json:"-"`
	Credential   string    `json:"-" gorm:"not null"`
	CreatedAt    time.Time `json:"-"`
}

type HostCredentials []HostCredential
