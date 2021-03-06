/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package postgres

import (
	"database/sql"
	"github.com/google/uuid"
	"github.com/jinzhu/gorm"
	"github.com/pkg/errors"
	"intel/isecl/shvs/v3/types"
)

type PostgresHostRepository struct {
	db *gorm.DB
}

func (r *PostgresHostRepository) Create(h *types.Host) (*types.Host, error) {
	log.Trace("repository/postgres/pg_host: Create() Entering")
	defer log.Trace("repository/postgres/pg_host: Create() Leaving")

	err := r.db.Create(h).Error
	return h, errors.Wrap(err, "Create: failed to create Host")
}

const (
	hostsFields   = "hosts.id, hosts.name, hosts.hardware_uuid"
	sgxDataFields = "host_sgx_data.sgx_supported, host_sgx_data.sgx_enabled, host_sgx_data.flc_enabled," +
		"host_sgx_data.epc_size, host_sgx_data.tcb_uptodate"
)

func (r *PostgresHostRepository) Retrieve(h *types.Host, criteria *types.HostInfoFetchCriteria) (*types.HostInfo, error) {
	log.Trace("repository/postgres/pg_host: Retrieve() Entering")
	defer log.Trace("repository/postgres/pg_host: Retrieve() Leaving")

	var host types.HostInfo
	slog.WithField("Host", h).Debug("Retrieve Call")

	var tx = r.db.Model(types.Host{})
	var err error
	var row *sql.Row
	sgx := types.SGX{}
	meta := types.SGXMeta{}

	if criteria != nil && (criteria.GetPlatformData || criteria.GetStatus){
		row = buildHostInfoFetchQuery(tx, criteria).Where(&h).Row()
		if criteria.GetPlatformData && criteria.GetStatus {
			err = row.Scan(&host.ID, &host.Name, &host.HardwareUUID, &sgx.Supported,
				&sgx.Enabled, &meta.FlcEnabled, &meta.EpcSize, &meta.TcbUpToDate, &host.Status)
		} else if criteria.GetPlatformData {
			err = row.Scan(&host.ID, &host.Name, &host.HardwareUUID, &sgx.Supported,
				&sgx.Enabled, &meta.FlcEnabled, &meta.EpcSize, &meta.TcbUpToDate, )
		} else if criteria.GetStatus {
			err = row.Scan(&host.ID, &host.Name, &host.HardwareUUID, &host.Status)
		}
	} else {
		err = tx.Select(hostsFields).Where(&h).Row().Scan(&host.ID, &host.Name, &host.HardwareUUID)
	}
	if err != nil {
		return nil, errors.Wrap(err, "Retrieve: failed to Retrieve Host")
	}

	if !*sgx.Supported {
		host.HardwareFeatures = nil
	} else {
		host.HardwareFeatures = &types.HardwareFeatures{SGX: &types.SGX{
			Enabled: sgx.Enabled,
			Meta:    &meta,
		}}
	}
	return &host, nil
}

func (r *PostgresHostRepository) GetHostQuery(queryData *types.Host, criteria *types.HostInfoFetchCriteria) ([]*types.HostInfo, error) {
	log.Trace("repository/postgres/pg_host: GetHostQuery() Entering")
	defer log.Trace("repository/postgres/pg_host: GetHostQuery() Leaving")

	hrs := []*types.HostInfo{}
	tx := buildHostSearchQuery(r.db, queryData)
	if tx == nil {
		return hrs, errors.New("Unexpected Error. Could not build a gorm query object in Hosts GetHostQuery function.")
	}
	if criteria != nil && (criteria.GetPlatformData || criteria.GetStatus) {
		tx = buildHostInfoFetchQuery(tx, criteria)
	} else {
		tx = tx.Select(hostsFields)
	}

	rows, err := tx.Rows()
	if err != nil {
		return nil, errors.Wrap(err, "GetHostQuery: failed to retrieve records from db")
	}
	defer func() {
		derr := rows.Close()
		if derr != nil {
			log.WithError(derr).Error("Error closing rows")
		}
	}()

	if criteria != nil && (criteria.GetPlatformData || criteria.GetStatus){
		hrs, err = getAdditionalHostInfo(criteria, rows)
	} else {
		for rows.Next() {
			host := types.HostInfo{}

			err = rows.Scan(&host.ID, &host.Name, &host.HardwareUUID)
			if err != nil {
				return nil, errors.Wrap(err, "GetHostQuery: failed to scan row from db")
			}
			hrs = append(hrs, &host)
		}
	}
	return hrs, nil
}

func buildHostInfoFetchQuery(tx *gorm.DB, criteria *types.HostInfoFetchCriteria) *gorm.DB {
	log.Trace("repository/postgres/pg_host: buildHostInfoFetchQuery() Entering")
	defer log.Trace("repository/postgres/pg_host: buildHostInfoFetchQuery() Leaving")

	if criteria.GetPlatformData && criteria.GetStatus {
		tx = tx.Select(hostsFields + ", " + sgxDataFields + ", host_statuses.status").
			Joins("left join host_sgx_data on host_sgx_data.host_id = hosts.id").
			Joins("left join host_statuses on host_statuses.host_id = hosts.id")

	} else if criteria.GetPlatformData {
		tx = tx.Select(hostsFields + ", " + sgxDataFields).
			Joins("left join host_sgx_data on host_sgx_data.host_id = hosts.id")

	} else if criteria.GetStatus {
		tx = tx.Select(hostsFields + ", host_statuses.status").
			Joins("left join host_statuses on host_statuses.host_id = hosts.id")
	}

	return tx
}

func getAdditionalHostInfo(criteria *types.HostInfoFetchCriteria, rows *sql.Rows) ([]*types.HostInfo, error) {

	var err error
	hrs := []*types.HostInfo{}
	for rows.Next() {
		host := types.HostInfo{}
		sgx := types.SGX{}
		meta := types.SGXMeta{}

		if criteria.GetPlatformData && criteria.GetStatus {
			err = rows.Scan(&host.ID, &host.Name, &host.HardwareUUID, &sgx.Supported,
				&sgx.Enabled, &meta.FlcEnabled, &meta.EpcSize, &meta.TcbUpToDate, &host.Status)
		} else if criteria.GetPlatformData {
			err = rows.Scan(&host.ID, &host.Name, &host.HardwareUUID, &sgx.Supported,
				&sgx.Enabled, &meta.FlcEnabled, &meta.EpcSize, &meta.TcbUpToDate)
		} else if criteria.GetStatus {
			err = rows.Scan(&host.ID, &host.Name, &host.HardwareUUID, &host.Status)
		} else {
			err = rows.Scan(&host.ID, &host.Name, &host.HardwareUUID)
		}
		if err != nil {
			return nil, errors.Wrap(err, "getAdditionalHostInfo: failed to scan row from db")
		}

		if !*sgx.Supported {
			host.HardwareFeatures = nil
		} else {
			host.HardwareFeatures = &types.HardwareFeatures{SGX: &types.SGX{
				Enabled: sgx.Enabled,
				Meta:    &meta,
			}}
		}

		hrs = append(hrs, &host)
	}
	return hrs, nil
}

func buildHostSearchQuery(tx *gorm.DB, rs *types.Host) *gorm.DB {
	log.Trace("repository/postgres/pg_host: buildHostSearchQuery() Entering")
	defer log.Trace("repository/postgres/pg_host: buildHostSearchQuery() Leaving")

	if tx == nil {
		return nil
	}

	tx = tx.Model(&types.Host{})

	if rs.HardwareUUID != uuid.Nil {
		tx = tx.Where("hardware_uuid = (?)", rs.HardwareUUID)
	}
	if rs.Name != "" {
		tx = tx.Where("Name = (?)", rs.Name)
	}
	tx = tx.Where("deleted='f'")
	return tx
}

func (r *PostgresHostRepository) Update(h *types.Host) error {
	log.Trace("repository/postgres/pg_host: Update() Entering")
	defer log.Trace("repository/postgres/pg_host: Update() Leaving")

	if err := r.db.Save(h).Error; err != nil {
		return errors.Wrap(err, "Update: failed to update Host")
	}
	return nil
}

func (r *PostgresHostRepository) Delete(h *types.Host) error {
	log.Trace("repository/postgres/pg_host: Delete() Entering")
	defer log.Trace("repository/postgres/pg_host: Delete() Leaving")

	if err := r.db.Delete(h).Error; err != nil {
		return errors.Wrap(err, "Delete: failed to delete Host")
	}
	return nil
}
