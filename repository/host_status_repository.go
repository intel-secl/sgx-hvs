/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package repository

import "intel/isecl/sgx-host-verification-service/types"

type HostStatusRepository interface {
	Create(types.HostStatus) (*types.HostStatus, error)
	Retrieve(types.HostStatus) (*types.HostStatus, error)
	RetrieveAll(user types.HostStatus) (types.HostsStatus, error)
	RetrieveAllQueues(in []string) (types.HostsStatus, error)
	Update(types.HostStatus) error
	Delete(types.HostStatus) error
	GetHostStateInfo() (types.HostsStatus, error)
}
