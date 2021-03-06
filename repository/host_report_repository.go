/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package repository

import (
	"intel/isecl/shvs/v3/types"
)

type HostReportRepository interface {
	Create(*types.HostReport) (*types.HostReport, error)
	Retrieve(*types.HostReport) (*types.HostReport, error)
	RetrieveAll(*types.HostReport) (*types.HostReports, error)
	Update(*types.HostReport) error
	Delete(*types.HostReport) error
	GetHostReportQuery(*types.SgxHostReportInputData) (*types.HostReports, error)
}
