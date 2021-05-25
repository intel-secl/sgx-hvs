/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package postgres

import (
	"github.com/jinzhu/gorm"
	"github.com/pkg/errors"
	"intel/isecl/shvs/v4/types"
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

func (r *PostgresHostStatusRepository) RetrieveExpiredHosts() (types.HostStatuses, error) {
	log.Trace("repository/postgres/pg_host_status: RetrieveExpiredHosts() Entering")
	defer log.Trace("repository/postgres/pg_host_status: RetrieveExpiredHosts() Leaving")

	var hs types.HostStatuses
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
