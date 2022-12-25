/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package repository

import (
	"intel/isecl/shvs/v5/types"
)

type HostStatusRepository interface {
	Create(*types.HostStatus) (*types.HostStatus, error)
	Retrieve(*types.HostStatus) (*types.HostStatus, error)
	Update(*types.HostStatus) error
	RetrieveExpiredHosts() (types.HostStatuses, error)
	RetrieveNonExpiredHost(*types.HostStatus) (*types.HostStatus, error)
}
