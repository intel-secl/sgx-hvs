/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package types

import (
	"github.com/google/uuid"
	"time"
)

// Host struct is the database schema of a Host table
type Host struct {
	// swagger:strfmt uuid
	ID          uuid.UUID `json:"host_ID" gorm:"type:uuid;unique;primary_key;"`
	Name        string    `json:"host_name" gorm:"index:idx_hostname;not null;unique"`
	Description string    `json:"-"`
	// swagger:strfmt uuid
	HardwareUUID uuid.UUID `json:"uuid" gorm:"type:uuid"`
	CreatedTime  time.Time `json:"-"`
	UpdatedTime  time.Time `json:"-"`
	Deleted      bool      `json:"-" gorm:"type:bool;not null;default:false"`
}

type HostStatusInfo struct {
	Host
	Status *string `json:"status,omitempty"`
}

type HostInfo struct {
	HostStatusInfo
	HardwareFeatures *HardwareFeatures `json:"hardware_features,omitempty"`
}

type HardwareFeatures struct {
	SGX *SGX `json:"SGX,omitempty"`
}

type SGX struct {
	Supported *bool    `json:"-"`
	Enabled   *bool    `json:"enabled,omitempty"`
	Meta      *SGXMeta `json:"meta,omitempty"`
}

type SGXMeta struct {
	FlcEnabled  *bool   `json:"flc_enabled,omitempty"`
	EpcSize     *string `json:"epc_size,omitempty"`
	TcbUpToDate *bool   `json:"tcb_upToDate,omitempty"`
}

type Hosts []HostInfo
