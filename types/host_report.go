/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package types

import (
	"time"
)

// Report struct is the database schema of a Report table
type HostReport struct {
	Id             string    `json:"-" gorm:"type:uuid;primary_key"`
	HostId         string    `json:"-" gorm:"type:uuid;not null"`
	TrustReport    string    `json:"-" gorm:"not null"`
	CreatedTime    time.Time `json:"-"`
	ExpirationTime time.Time `json:"-"`
	Saml           string    `json:"-"`
}

type SgxHostReportInputData struct {
	Id             string
	HostId         string
	HostHardwareId string
	HostName       string
	Status         string
	LatestperHost  bool
}

type HostReports []HostReport
