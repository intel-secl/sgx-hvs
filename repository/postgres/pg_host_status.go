/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package postgres

import (
	"github.com/jinzhu/gorm"
	"github.com/pkg/errors"
	"intel/isecl/shvs/v3/types"
	"time"
)

type PostgresHostStatusRepository struct {
	db *gorm.DB
}

func (r *PostgresHostStatusRepository) Create(h *types.HostStatus) (*types.HostStatus, error) {
	log.Trace("repository/postgres/pg_host_status: Create() Entering")
	defer log.Trace("repository/postgres/pg_host_status: Create() Leaving")

	err := r.db.Create(h).Error
	return h, errors.Wrap(err, "Create(): failed to create HostStatus")
}

func (r *PostgresHostStatusRepository) Retrieve(h *types.HostStatus) (*types.HostStatus, error) {
	log.Trace("repository/postgres/pg_host_status: Retrieve() Entering")
	defer log.Trace("repository/postgres/pg_host_status: Retrieve() Leaving")

	var p types.HostStatus
	slog.WithField("HostStatus", h).Debug("Retrieve Call")
	err := r.db.Where(h).First(&p).Error
	if err != nil {
		log.Trace("Error in fetch records Entering")
		return nil, errors.Wrap(err, "Retrieve(): failed to Retrieve HostStatus")
	}
	return &p, nil
}

func (r *PostgresHostStatusRepository) RetrieveAll(h *types.HostStatus) (*types.HostsStatus, error) {
	log.Trace("repository/postgres/pg_host_status: RetrieveAll() Entering")
	defer log.Trace("repository/postgres/pg_host_status: RetrieveAll() Leaving")

	var hs types.HostsStatus
	err := r.db.Where(h).Find(&hs).Error
	if err != nil {
		return nil, errors.Wrap(err, "RetrieveAll(): failed to RetrieveAll HostStatus")
	}

	slog.WithField("db hs", hs).Trace("RetrieveAll")
	return &hs, errors.Wrap(err, "RetrieveAll(): failed to RetrieveAll HostStatus")
}

func (r *PostgresHostStatusRepository) RetrieveAllQueues(status []string) (*types.HostsStatus, error) {
	log.Trace("repository/postgres/pg_host_status: RetrieveAllQueues() Entering")
	defer log.Trace("repository/postgres/pg_host_status: RetrieveAllQueues() Leaving")

	var hs types.HostsStatus
	err := r.db.Where("status IN (?)", status).Find(&hs).Error
	if err != nil {
		return nil, errors.Wrap(err, "RetrieveAllQueues(): failed to RetrieveAll HostStatus")
	}

	slog.WithField("db hs", hs).Trace("RetrieveAllQueues")
	return &hs, errors.Wrap(err, "RetrieveAllQueues(): failed to RetrieveAll HostStatus")
}

func (r *PostgresHostStatusRepository) RetrieveNonExpiredHost(h *types.HostStatus) (*types.HostStatus, error) {
	log.Trace("repository/postgres/pg_host_status: RetrieveNonExpiredHost() Entering")
	defer log.Trace("repository/postgres/pg_host_status: RetrieveNonExpiredHost() Leaving")

	var hs types.HostStatus
	err := r.db.Where("status = 'CONNECTED' and host_id = (?)", h.HostID).First(&hs).Error
	if err != nil {
		return nil, errors.Wrap(err, "RetrieveNonExpiredHost(): failed to RetrieveNonExpiredHost HostStatus")
	}
	slog.WithField("db hs", hs).Trace("RetrieveNonExpiredHost")
	return &hs, nil
}

func (r *PostgresHostStatusRepository) RetrieveExpiredHosts() (types.HostsStatus, error) {
	log.Trace("repository/postgres/pg_host_status: RetrieveExpiredHosts() Entering")
	defer log.Trace("repository/postgres/pg_host_status: RetrieveExpiredHosts() Leaving")

	var hs types.HostsStatus
	var currentTime = time.Now()
	err := r.db.Where("(expiry_time < (?) and STATUS in ('CONNECTED')) OR (STATUS in ('IN-ACTIVE'))", currentTime).Find(&hs).Error
	if err != nil {
		return nil, errors.Wrap(err, "RetrieveExpiredHosts: failed to RetrieveAll HostStatus")
	}

	slog.WithField("db hs", hs).Debug("RetrieveExpiredHosts")
	return hs, errors.Wrap(err, "RetrieveExpiredHosts(): failed to Retrieve ExpiredHosts id")
}

func (r *PostgresHostStatusRepository) Update(h *types.HostStatus) error {
	log.Trace("repository/postgres/pg_host_status: Update() Entering")
	defer log.Trace("repository/postgres/pg_host_status: Update() Leaving")

	if err := r.db.Save(h).Error; err != nil {
		return errors.Wrap(err, "Update(): failed to update HostStatus")
	}
	return nil
}

func (r *PostgresHostStatusRepository) Delete(h *types.HostStatus) error {
	log.Trace("repository/postgres/pg_host_status: Delete() Entering")
	defer log.Trace("repository/postgres/pg_host_status: Delete() Leaving")

	if err := r.db.Delete(h).Error; err != nil {
		return errors.Wrap(err, "Delete(): failed to delete HostStatus")
	}
	return nil
}

func (r *PostgresHostStatusRepository) GetHostStateInfo() (*types.HostsStatus, error) {
	log.Trace("repository/postgres/pg_host_status: GetHostStatusQuary() Entering")
	defer log.Trace("repository/postgres/pg_host_status: GetHostStatusQuary() Leaving")

	var hs types.HostsStatus

	query := `SELECT *FROM host_statuses WHERE host_id IN (SELECT Id FROM hosts WHERE deleted='f')`

	log.Debug("query:", query)

	r.db.Raw(query).Scan(&hs)
	if len(hs) == 0 {
		return nil, errors.New("GetHostStateInfo(): Could not retrieve host status")
	}
	return &hs, nil
}
