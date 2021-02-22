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

type PostgresHostReportRepository struct {
	db *gorm.DB
}

func (r *PostgresHostReportRepository) Create(hr *types.HostReport) (*types.HostReport, error) {
	log.Trace("repository/postgres/pg_report: Create() Entering")
	defer log.Trace("repository/postgres/pg_report: Create() Leaving")

	err := r.db.Create(hr).Error
	return hr, errors.Wrap(err, "Create: failed to create HostReport")
}

func (r *PostgresHostReportRepository) Retrieve(hr *types.HostReport) (*types.HostReport, error) {
	log.Trace("repository/postgres/pg_report: Retrieve() Entering")
	defer log.Trace("repository/postgres/pg_report: Retrieve() Leaving")

	var p types.HostReport
	slog.WithField("HostReport", hr).Debug("Retrieve Call")
	err := r.db.Where(hr).First(&p).Error
	if err != nil {
		log.Trace("Error in fetch records Entering")
		return nil, errors.Wrap(err, "Retrieve: failed to retrieve HostReport")
	}
	return &p, nil
}

func (r *PostgresHostReportRepository) RetrieveAll(hr *types.HostReport) (*types.HostReports, error) {
	log.Trace("repository/postgres/pg_report: RetrieveAll() Entering")
	defer log.Trace("repository/postgres/pg_report: RetrieveAll() Leaving")

	var hrs types.HostReports
	err := r.db.Where(hr).Find(&hrs).Error
	if err != nil {
		return nil, errors.Wrap(err, "RetrieveAll: failed to RetrieveAll HostReport")
	}

	slog.WithField("db hs", hrs).Trace("RetrieveAll")
	return &hrs, errors.Wrap(err, "RetrieveAll: failed to RetrieveAll HostReport")
}

func (r *PostgresHostReportRepository) Update(hr *types.HostReport) error {
	log.Trace("repository/postgres/pg_report: Update() Entering")
	defer log.Trace("repository/postgres/pg_report: Update() Leaving")

	if err := r.db.Save(hr).Error; err != nil {
		return errors.Wrap(err, "Update: failed to update HostReport")
	}
	return nil
}

func (r *PostgresHostReportRepository) Delete(hr *types.HostReport) error {
	log.Trace("repository/postgres/pg_report: Delete() Entering")
	defer log.Trace("repository/postgres/pg_report: Delete() Leaving")

	if err := r.db.Delete(hr).Error; err != nil {
		return errors.Wrap(err, "Delete: failed to delete HostReport")
	}
	return nil
}

func (r *PostgresHostReportRepository) GetHostReportQuery(queryData *types.SgxHostReportInputData) (*types.HostReports, error) {
	log.Trace("repository/postgres/pg_host: GetHostReportQuery() Entering")
	defer log.Trace("repository/postgres/pg_host: GetHostReportQuery() Leaving")

	var hrs types.HostReports
	var query string

	if queryData.LatestperHost {
		query = `SELECT hr.id, hr.host_id, hr.created_time, hr.expiration_time, hr.saml from host_reports as hr
		INNER JOIN ( SELECT hr.host_id as host_id, MAX(hr.created_time) date_info from host_reports as hr
		GROUP BY hr.host_id ) as mytable on mytable.host_id=hr.host_id AND mytable.date_info=hr.created_time
		INNER JOIN hosts as h on h.ID=hr.host_id  WHERE h.deleted='f'`
	} else {
		query = `SELECT hr.id, hr.host_id, hr.created_time, hr.expiration_time, hr.saml from host_reports as hr
		LEFT JOIN host_statuses as hs on hs.host_id=hr.host_id
		LEFT JOIN hosts as h on hr.host_id=h.ID WHERE h.deleted='f'`
	}

	if queryData.ID != "" {
		query = query + " AND hr.id = '" + queryData.ID + "'"
	}
	if queryData.HostID != "" {
		query = query + " AND h.ID = '" + queryData.HostID + "'"
	}
	if queryData.HostHardwareID != "" {
		query = query + " AND h.hardware_uuid = '" + queryData.HostHardwareID + "'"
	}
	if queryData.HostName != "" {
		query = query + " AND h.name = '" + queryData.HostName + "'"
	}
	if queryData.Status != "" {
		query = query + " AND hs.status = '" + queryData.Status + "'"
	}

	log.Debug("query:", query)

	r.db.Raw(query).Scan(&hrs)
	if len(hrs) == 0 {
		return nil, errors.New("GetHostReportQuery(): Could not find reports in Database")
	}
	return &hrs, nil
}
