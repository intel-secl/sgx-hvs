/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package postgres

import (
	"intel/isecl/sgx-host-verification-service/types"
	"github.com/jinzhu/gorm"
	"github.com/pkg/errors"
)

type PostgresHostCredentialRepository struct {
	db *gorm.DB
}

func (r *PostgresHostCredentialRepository) Create(h types.HostCredential) (*types.HostCredential, error) {
	log.Trace("repository/postgres/pg_host_credential: Create() Entering")
	defer log.Trace("repository/postgres/pg_host_credential: Create() Leaving")

	err := r.db.Create(&h).Error
	return &h, errors.Wrap(err, "Create: failed to create HostCredential")
}

func (r *PostgresHostCredentialRepository) Retrieve(h types.HostCredential) (*types.HostCredential, error) {
	log.Trace("repository/postgres/pg_host_credential: Retrieve() Entering")
	defer log.Trace("repository/postgres/pg_host_credential: Retrieve() Leaving")

	var p types.HostCredential
	slog.WithField("HostCredential", h).Debug("Retrieve Call")
	err := r.db.Where(&h).First(&p).Error
	if err != nil {
		log.Trace("Error in fetch records Entering")
		return nil, errors.Wrap(err, "Retrieve: failed to Retrieve HostCredential")
	}
	return &p, nil
}

func (r *PostgresHostCredentialRepository) RetrieveAll(h types.HostCredential) (types.HostCredentials, error) {
	log.Trace("repository/postgres/pg_host_credential: RetrieveAll() Entering")
	defer log.Trace("repository/postgres/pg_host_credential: RetrieveAll() Leaving")

	var hs types.HostCredentials
	err := r.db.Where(&h).Find(&hs).Error
	if err != nil {
		return nil, errors.Wrap(err, "RetrieveAll: failed to RetrieveAll HostCredential")
	}

	slog.WithField("db hs", hs).Trace("RetrieveAll")
	return hs, errors.Wrap(err, "RetrieveAll: failed to RetrieveAll HostCredential")
}

func (r *PostgresHostCredentialRepository) Update(h types.HostCredential) error {
	log.Trace("repository/postgres/pg_host_credential: Update() Entering")
	defer log.Trace("repository/postgres/pg_host_credential: Update() Leaving")

	if err := r.db.Save(&h).Error; err != nil {
		return errors.Wrap(err, "Update: failed to update HostCredential")
	}
	return nil
}

func (r *PostgresHostCredentialRepository) Delete(h types.HostCredential) error {
	log.Trace("repository/postgres/pg_host_credential: Delete() Entering")
	defer log.Trace("repository/postgres/pg_host_credential: Delete() Leaving")

	if err := r.db.Delete(&h).Error; err != nil {
		return errors.Wrap(err, "Delete: failed to delete HostCredential")
	}
	return nil
}

