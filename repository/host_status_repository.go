/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package repository

import (
	"intel/isecl/shvs/types"
)

type HostStatusRepository interface {
	Create(types.HostStatus) (*types.HostStatus, error)
	Retrieve(types.HostStatus) (*types.HostStatus, error)
	RetrieveAll(user types.HostStatus) (types.HostsStatus, error)
	RetrieveAllQueues(in []string) (types.HostsStatus, error)
	Update(types.HostStatus) error
	Delete(types.HostStatus) error
	GetHostStateInfo() (types.HostsStatus, error)
	RetrieveExpiredHosts() (types.HostsStatus, error)
	RetrieveNonExpiredHost(types.HostStatus) (*types.HostStatus, error)
}
