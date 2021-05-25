/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package repository

import "intel/isecl/shvs/v4/types"

type HostRepository interface {
	Create(*types.Host) (*types.Host, error)
	Retrieve(*types.Host, *types.HostInfoFetchCriteria) (*types.HostInfo, error)
	RetrieveAnyIfExists(*types.Host) (*types.HostInfo, error)
	GetHostQuery(*types.Host, *types.HostInfoFetchCriteria) ([]*types.HostInfo, error)
	Update(*types.Host) error
	Delete(*types.Host) error
}
