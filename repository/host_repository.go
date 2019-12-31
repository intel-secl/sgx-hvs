/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package repository

import "intel/isecl/sgx-host-verification-service/types"

type HostRepository interface {
	Create(types.Host) (*types.Host, error)
	Retrieve(types.Host) (*types.Host, error)
	RetrieveAll(user types.Host) (types.Hosts, error)
	Update(types.Host) error
	Delete(types.Host) error
}
