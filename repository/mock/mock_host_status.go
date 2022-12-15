/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package mock

import (
	"errors"
	"intel/isecl/lib/common/v5/validation"
	"intel/isecl/shvs/v5/types"

	"github.com/google/uuid"
	commErr "github.com/intel-secl/intel-secl/v5/pkg/lib/common/err"
)

type MockHostStatusRepository struct {
	HostStatusRepo []types.HostStatus
}

func (m *MockHostStatusRepository) Create(h *types.HostStatus) (*types.HostStatus, error) {
	thisHostStatus := types.HostStatus{
		ID:          h.ID,
		HostID:      h.HostID,
		Status:      h.Status,
		CreatedTime: h.CreatedTime,
		UpdatedTime: h.UpdatedTime,
		ExpiryTime:  h.UpdatedTime,
	}
	m.HostStatusRepo = append(m.HostStatusRepo, thisHostStatus)
	return &thisHostStatus, nil
}

func (m *MockHostStatusRepository) Retrieve(h *types.HostStatus) (*types.HostStatus, error) {

	if h.HostID != uuid.Nil {
		validationErr := validation.ValidateUUIDv4(h.HostID.String())
		if validationErr != nil {
			return nil, &commErr.ResourceError{Message: validationErr.Error()}
		}
		for _, thisHostStatus := range m.HostStatusRepo {
			if thisHostStatus.ID == h.HostID {
				return &thisHostStatus, nil
			}
		}
	}

	if h.ID != uuid.Nil {
		validationErr := validation.ValidateUUIDv4(h.ID.String())
		if validationErr != nil {
			return nil, &commErr.ResourceError{Message: validationErr.Error()}
		}
		for _, thisHostStatus := range m.HostStatusRepo {
			if thisHostStatus.ID == h.ID {
				return &thisHostStatus, nil
			}
		}
	}
	return nil, errors.New("record not found")
}

func (m *MockHostStatusRepository) RetrieveNonExpiredHost(h *types.HostStatus) (*types.HostStatus, error) {
	for _, thisHost := range m.HostStatusRepo {
		if thisHost.ID == h.ID || thisHost.HostID == h.HostID {
			return &thisHost, nil
		}
	}
	return nil, nil
}

func (m *MockHostStatusRepository) RetrieveExpiredHosts() (types.HostStatuses, error) {
	return nil, nil
}

func (m *MockHostStatusRepository) Update(h *types.HostStatus) error {
	return nil
}
