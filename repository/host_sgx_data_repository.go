/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package repository

import (
	"intel/isecl/shvs/types"
	"time"
)

type HostSgxDataRepository interface {
	Create(types.HostSgxData) (*types.HostSgxData, error)
	Retrieve(types.HostSgxData) (*types.HostSgxData, error)
	RetrieveAll(user types.HostSgxData) (types.HostsSgxData, error)
	Update(types.HostSgxData) error
	Delete(types.HostSgxData) error
	GetPlatformData(updatedTime time.Time) (types.HostsSgxData, error)
}
