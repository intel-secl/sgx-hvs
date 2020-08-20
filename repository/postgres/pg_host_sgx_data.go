/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package postgres

import (
	"github.com/jinzhu/gorm"
	"github.com/pkg/errors"
	"intel/isecl/shvs/types"
	"time"
)

type PostgresHostSgxDataRepository struct {
	db *gorm.DB
}

func (r *PostgresHostSgxDataRepository) Create(h types.HostSgxData) (*types.HostSgxData, error) {
	log.Trace("repository/postgres/pg_host_sgx_data: Create() Entering")
	defer log.Trace("repository/postgres/pg_host_sgx_data: Create() Leaving")

	err := r.db.Create(&h).Error
	return &h, errors.Wrap(err, "Create(): failed to create HostSgxData")
}

func (r *PostgresHostSgxDataRepository) Retrieve(h types.HostSgxData) (*types.HostSgxData, error) {
	log.Trace("repository/postgres/pg_host_sgx_data: Retrieve() Entering")
	defer log.Trace("repository/postgres/pg_host_sgx_data: Retrieve() Leaving")

	var p types.HostSgxData
	slog.WithField("HostSgxData", h).Debug("Retrieve Call")
	err := r.db.Where(&h).First(&p).Error
	if err != nil {
		log.Trace("Error in fetch records Entering")
		return nil, errors.Wrap(err, "Retrieve(): failed to Retrieve HostSgxData")
	}
	return &p, nil
}

func (r *PostgresHostSgxDataRepository) RetrieveAll(h types.HostSgxData) (types.HostsSgxData, error) {
	log.Trace("repository/postgres/pg_host_sgx_data: RetrieveAll() Entering")
	defer log.Trace("repository/postgres/pg_host_sgx_data: RetrieveAll() Leaving")

	var hs types.HostsSgxData
	cols := "host_sgx_data.host_id, host_sgx_data.sgx_supported, host_sgx_data.sgx_enabled, host_sgx_data.flc_enabled, host_sgx_data.epc_size, host_sgx_data.tcb_uptodate"

	tx := r.db.Joins("INNER JOIN host_statuses on host_statuses.host_id = host_sgx_data.host_id").Where("status = 'CONNECTED' and host_statuses.host_id = (?)", h.HostId)
	tx = tx.Select(cols)
	err := tx.Find(&hs).Error
	if err != nil {
		return nil, errors.Wrap(err, "RetrieveAll(): failed to RetrieveAll HostSgxData")
	}
	slog.WithField("db hs", hs).Trace("RetrieveAll")
	return hs, errors.Wrap(err, "RetrieveAll(): failed to RetrieveAll HostSgxData")
}

func (r *PostgresHostSgxDataRepository) GetPlatformData(timeIntervalFilter time.Time) (types.HostsSgxData, error) {
	log.Trace("repository/postgres/pg_host_sgx_data: GetPlatformData() Entering")
	defer log.Trace("repository/postgres/pg_host_sgx_data: GetPlatformData() Leaving")

	var hs types.HostsSgxData
	cols := "host_sgx_data.host_id, host_sgx_data.sgx_supported, host_sgx_data.sgx_enabled, host_sgx_data.flc_enabled, host_sgx_data.epc_size, host_sgx_data.tcb_uptodate"

	tx := r.db.Joins("INNER JOIN host_statuses on host_statuses.host_id = host_sgx_data.host_id").Where("status = 'CONNECTED' AND updated_time >= (?)", timeIntervalFilter)
	tx = tx.Select(cols)
	err := tx.Find(&hs).Error
	if err != nil {
		return nil, errors.Wrap(err, "GetPlatformData(): failed to RetrieveByHostId HostSgxData")
	}

	slog.WithField("db hs", hs).Info("getPlatformData")
	return hs, nil
}

func (r *PostgresHostSgxDataRepository) Update(h types.HostSgxData) error {
	log.Trace("repository/postgres/pg_host_sgx_data: Update() Entering")
	defer log.Trace("repository/postgres/pg_host_sgx_data: Update() Leaving")

	if err := r.db.Save(&h).Error; err != nil {
		return errors.Wrap(err, "Update(): failed to update HostSgxData")
	}
	return nil
}

func (r *PostgresHostSgxDataRepository) Delete(h types.HostSgxData) error {
	log.Trace("repository/postgres/pg_host_sgx_data: Delete() Entering")
	defer log.Trace("repository/postgres/pg_host_sgx_data: Delete() Leaving")

	if err := r.db.Delete(&h).Error; err != nil {
		return errors.Wrap(err, "Delete(): failed to delete HostSgxData")
	}
	return nil
}
