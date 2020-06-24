/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package repository

import "intel/isecl/shvs/types"

type HostCredentialRepository interface {
	Create(types.HostCredential) (*types.HostCredential, error)
	Retrieve(types.HostCredential) (*types.HostCredential, error)
	RetrieveAll(user types.HostCredential) (types.HostCredentials, error)
	Update(types.HostCredential) error
	Delete(types.HostCredential) error
}
