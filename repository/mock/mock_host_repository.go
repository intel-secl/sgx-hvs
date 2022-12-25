/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package mock

import (
	"errors"
	"intel/isecl/shvs/v5/types"

	"github.com/google/uuid"
	"github.com/jinzhu/gorm"
)

type MockHostRepository struct {
	Host []types.Host
}

func (m *MockHostRepository) Create(h *types.Host) (*types.Host, error) {
	thisHost := types.Host{
		ID:           h.ID,
		Name:         h.Name,
		Description:  h.Description,
		HardwareUUID: h.HardwareUUID,
		CreatedTime:  h.CreatedTime,
		UpdatedTime:  h.UpdatedTime,
		Deleted:      h.Deleted,
	}
	if h.HardwareUUID == uuid.Nil {
		thisHost.HardwareUUID = uuid.New()
	}
	m.Host = append(m.Host, thisHost)
	return &thisHost, nil
}

func (m *MockHostRepository) Retrieve(h *types.Host, criteria *types.HostInfoFetchCriteria) (*types.HostInfo, error) {
	if h.ID != uuid.Nil {
		for _, thisHostStatus := range m.Host {
			if thisHostStatus.ID == h.ID {
				hostInfo := types.HostInfo{
					HostStatusInfo: types.HostStatusInfo{
						Host: thisHostStatus,
					},
				}
				return &hostInfo, nil
			}
		}
	}

	if h.Name != "" {
		for _, thisHostStatus := range m.Host {
			if thisHostStatus.Name == h.Name {
				hostInfo := types.HostInfo{
					HostStatusInfo: types.HostStatusInfo{
						Host: thisHostStatus,
					},
				}
				return &hostInfo, nil
			}
		}
	}
	return nil, errors.New("no records found")
}

func (m *MockHostRepository) RetrieveAnyIfExists(h *types.Host) (*types.Host, error) {

	// To validate if hosts already exists.
	for _, host := range m.Host {
		if h.ID != uuid.Nil && (h.ID == host.ID) || h.Name != "" && (h.Name == host.Name) {
			return &host, nil
		}
	}

	if h.Name == "TEST-HOST-NAME" {
		return nil, gorm.ErrInvalidTransaction // To simulate some internal server error.
	}
	return nil, gorm.ErrRecordNotFound
}

func (m *MockHostRepository) GetHostQuery(queryData *types.Host, criteria *types.HostInfoFetchCriteria) ([]*types.HostInfo, error) {
	var hosts []*types.HostInfo

	if queryData.Name != "" {
		for _, thisHost := range m.Host {
			if thisHost.Name == queryData.Name || thisHost.HardwareUUID == queryData.HardwareUUID {
				hostInfo := types.HostInfo{
					HostStatusInfo: types.HostStatusInfo{
						Host: thisHost,
					},
				}
				hosts = append(hosts, &hostInfo)
			}
		}
	}

	if queryData.HardwareUUID != uuid.Nil {
		for _, thisHost := range m.Host {
			if thisHost.HardwareUUID == queryData.HardwareUUID {
				hostInfo := types.HostInfo{
					HostStatusInfo: types.HostStatusInfo{
						Host: thisHost,
					},
				}
				hosts = append(hosts, &hostInfo)
			}
		}
	}

	return hosts, nil
}

func (m *MockHostRepository) Update(h *types.Host) error {

	return nil
}

func (m *MockHostRepository) Delete(h *types.Host) error {
	for _, thisHostStatus := range m.Host {
		if thisHostStatus.ID == h.ID {
			return nil
		}
	}
	return errors.New("no records found")
}
