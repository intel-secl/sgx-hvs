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
	Id           string    `json:"-" gorm:"primary_key;"`
	HostId       string    `json:"host_id" gorm:"type:uuid;not null"`
	SgxSupported bool      `json:"sgx_supported"`
	SgxEnabled   bool      `json:"sgx_enabled"`
	FlcEnabled   bool      `json:"flc_enabled"`
	EpcAddr      string    `json:"-"`
	EpcSize      string    `json:"epc_size"`
	TcbUptodate  bool      `json:"tcb_upToDate"`
	CreatedTime  time.Time `json:"-"`
}
type HostsSgxData []HostSgxData
