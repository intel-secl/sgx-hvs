/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package mock

import (
	"intel/isecl/shvs/repository"
)

type MockDatabase struct {
	MockPlatformTcbRepository MockPlatformTcbRepository
	MockPckCrlRepository MockPckCrlRepository
        MockPckCertRepository MockPckCertRepository
	MockPckCertChainRepository MockPckCertChainRepository
	MockFmspcTcbInfoRepository MockFmspcTcbInfoRepository
	MockQEIdentityRepository MockQEIdentityRepository
}

func (m *MockDatabase) Migrate() error {
	return nil
}

func (m *MockDatabase) PlatformTcbRepository() repository.PlatformTcbRepository {
	return &m.MockPlatformTcbRepository
}

func (m *MockDatabase) PckCrlRepository() repository.PckCrlRepository {
	return &m.MockPckCrlRepository
}
func (m *MockDatabase) PckCertRepository() repository.PckCertRepository {
	return &m.MockPckCertRepository
}
func (m *MockDatabase) PckCertChainRepository() repository.PckCertChainRepository {
	return &m.MockPckCertChainRepository
}
func (m *MockDatabase) FmspcTcbInfoRepository() repository.FmspcTcbInfoRepository {
	return &m.MockFmspcTcbInfoRepository
}
func (m *MockDatabase) QEIdentityRepository() repository.QEIdentityRepository {
	return &m.MockQEIdentityRepository
}

func (m *MockDatabase) Close() {

}
