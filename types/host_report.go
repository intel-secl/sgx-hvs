/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package types

import (
	"time"
)

// HostReport struct is the database schema of a Report table
type HostReport struct {
	ID             string    `json:"-" gorm:"type:uuid;primary_key"`
	HostID         string    `json:"-" gorm:"type:uuid;not null"`
	TrustReport    string    `json:"-" gorm:"not null"`
	CreatedTime    time.Time `json:"-"`
	ExpirationTime time.Time `json:"-"`
	Saml           string    `json:"-"`
}

type SgxHostReportInputData struct {
	ID             string
	HostID         string
	HostHardwareID string
	HostName       string
	Status         string
	LatestperHost  bool
}

type HostReports []HostReport
