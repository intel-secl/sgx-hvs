/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package postgres

import (
	"github.com/jinzhu/gorm"
	"github.com/pkg/errors"
	"intel/isecl/shvs/v3/types"
)

type PostgresHostRepository struct {
	db *gorm.DB
}

func (r *PostgresHostRepository) Create(h types.Host) (*types.Host, error) {
	log.Trace("repository/postgres/pg_host: Create() Entering")
	defer log.Trace("repository/postgres/pg_host: Create() Leaving")

	err := r.db.Create(&h).Error
	return &h, errors.Wrap(err, "Create: failed to create Host")
}

func (r *PostgresHostRepository) Retrieve(h types.Host) (*types.Host, error) {
	log.Trace("repository/postgres/pg_host: Retrieve() Entering")
	defer log.Trace("repository/postgres/pg_host: Retrieve() Leaving")

	var p types.Host
	slog.WithField("Host", h).Debug("Retrieve Call")
	err := r.db.Where(&h).First(&p).Error
	if err != nil {
		return nil, errors.Wrap(err, "Retrieve: failed to Retrieve Host")
	}
	return &p, nil
}

func (r *PostgresHostRepository) RetrieveAll(h types.Host) (types.Hosts, error) {
	log.Trace("repository/postgres/pg_host: RetrieveAll() Entering")
	defer log.Trace("repository/postgres/pg_host: RetrieveAll() Leaving")

	var hs types.Hosts
	err := r.db.Where(&h).Find(&hs).Error
	if err != nil {
		return nil, errors.Wrap(err, "RetrieveAll: failed to RetrieveAll Host")
	}

	slog.WithField("db hs", hs).Trace("RetrieveAll")
	return hs, errors.Wrap(err, "RetrieveAll: failed to RetrieveAll Host")
}

func (r *PostgresHostRepository) GetHostQuery(queryData *types.Host) (types.Hosts, error) {
	log.Trace("repository/postgres/pg_host: GetHostQuery() Entering")
	defer log.Trace("repository/postgres/pg_host: GetHostQuery() Leaving")

	var hrs types.Hosts
	tx := buildHostSearchQuery(r.db, queryData)
	if tx == nil {
		return hrs, errors.New("Unexpected Error. Could not build a gorm query object in Hosts RetrieveAll function.")
	}
	if err := tx.Find(&hrs).Error; err != nil {
		return hrs, errors.Wrap(err, "GetHostQuery: failed to retrieve hosts based on query parameters")
	}
	return hrs, nil
}

func buildHostSearchQuery(tx *gorm.DB, rs *types.Host) *gorm.DB {
	log.Trace("repository/postgres/pg_host: buildHostSearchQuery() Entering")
	defer log.Trace("repository/postgres/pg_host: buildHostSearchQuery() Leaving")

	if tx == nil {
		return nil
	}

	if len(rs.HardwareUUID) != 0 {
		tx = tx.Where("hardware_uuid = (?)", rs.HardwareUUID)
	}
	if len(rs.Name) != 0 {
		tx = tx.Where("Name = (?)", rs.Name)
	}
	tx = tx.Where("deleted='f'")
	return tx
}

func (r *PostgresHostRepository) Update(h types.Host) error {
	log.Trace("repository/postgres/pg_host: Update() Entering")
	defer log.Trace("repository/postgres/pg_host: Update() Leaving")

	if err := r.db.Save(&h).Error; err != nil {
		return errors.Wrap(err, "Update: failed to update Host")
	}
	return nil
}

func (r *PostgresHostRepository) Delete(h types.Host) error {
	log.Trace("repository/postgres/pg_host: Delete() Entering")
	defer log.Trace("repository/postgres/pg_host: Delete() Leaving")

	if err := r.db.Delete(&h).Error; err != nil {
		return errors.Wrap(err, "Delete: failed to delete Host")
	}
	return nil
}
