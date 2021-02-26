/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package types

import (
	"github.com/google/uuid"
	"time"
)

// HostStatus struct is the database schema of a HostStatus table
type HostStatus struct {
	ID          uuid.UUID `json:"-" gorm:"type:uuid;primary_key"`
	HostID      uuid.UUID `json:"-" gorm:"type:uuid;not null"`
	Status      string    `json:"-"`
	CreatedTime time.Time `json:"-"`
	UpdatedTime time.Time `json:"-"`
	ExpiryTime  time.Time `json:"validTo"`
}

type HostsStatus []HostStatus
