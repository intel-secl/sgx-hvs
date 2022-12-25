/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package mock

import (
	"intel/isecl/shvs/v5/repository"
)

type MockDatabase struct {
	MockHostRepository        MockHostRepository
	MockHostStatusRepository  MockHostStatusRepository
	MockHostSgxDataRepository MockHostSgxDataRepository
}

func NewMockDatabase(hostRepo MockHostRepository, hostStatusRepo MockHostStatusRepository, hostSgxRepo MockHostSgxDataRepository) repository.SHVSDatabase {
	return &MockDatabase{
		MockHostRepository:        hostRepo,
		MockHostStatusRepository:  hostStatusRepo,
		MockHostSgxDataRepository: hostSgxRepo,
	}
}

func (m *MockDatabase) Migrate() error {
	return nil
}

func (m *MockDatabase) HostRepository() repository.HostRepository {
	return &m.MockHostRepository
}

func (m *MockDatabase) HostStatusRepository() repository.HostStatusRepository {
	return &m.MockHostStatusRepository
}

func (m *MockDatabase) HostSgxDataRepository() repository.HostSgxDataRepository {
	return &m.MockHostSgxDataRepository
}

func (m *MockDatabase) Close() {

}
