/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package mock

import (
	"errors"
	"intel/isecl/shvs/v5/types"
	"time"
)

type MockHostSgxDataRepository struct {
	HostSGXData types.HostsSgxData
}

func (m *MockHostSgxDataRepository) Create(h *types.HostSgxData) (*types.HostSgxData, error) {
	thisSgxData := &types.HostSgxData{
		ID:           h.ID,
		HostID:       h.HostID,
		SgxSupported: h.SgxSupported,
		SgxEnabled:   h.SgxEnabled,
		FlcEnabled:   h.FlcEnabled,
		EpcAddr:      h.EpcAddr,
		EpcSize:      h.EpcSize,
		TcbUptodate:  h.TcbUptodate,
		CreatedTime:  h.CreatedTime,
	}
	m.HostSGXData = append(m.HostSGXData, *thisSgxData)
	return thisSgxData, nil
}

func (m *MockHostSgxDataRepository) Retrieve(h *types.HostSgxData) (*types.HostSgxData, error) {
	for _, platformData := range m.HostSGXData {
		if platformData.ID == h.ID {
			return &platformData, nil
		}
	}
	return nil, errors.New("no records found")
}

func (m *MockHostSgxDataRepository) RetrieveAll(h *types.HostSgxData) (*types.HostsSgxData, error) {

	return &m.HostSGXData, nil
}

func (m *MockHostSgxDataRepository) GetPlatformData(timeIntervalFilter time.Time) (*types.HostsSgxData, error) {
	return &m.HostSGXData, nil
}

func (m *MockHostSgxDataRepository) Update(h *types.HostSgxData) error {
	return nil
}

func (m *MockHostSgxDataRepository) Delete(h *types.HostSgxData) error {
	return nil
}
