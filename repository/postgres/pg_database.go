/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package postgres

import (
	"fmt"
	commLog "intel/isecl/lib/common/v4/log"
	commLogMsg "intel/isecl/lib/common/v4/log/message"
	"intel/isecl/shvs/v4/constants"
	"intel/isecl/shvs/v4/repository"
	"intel/isecl/shvs/v4/types"
	"strings"
	"time"

	"github.com/jinzhu/gorm"
)

var log = commLog.GetDefaultLogger()
var slog = commLog.GetSecurityLogger()

type PostgresDatabase struct {
	DB *gorm.DB
}

func (pd *PostgresDatabase) Migrate() error {
	log.Trace("repository/postgres/pg_database: Migrate() Entering")
	defer log.Trace("repository/postgres/pg_database: Migrate() Leaving")

	pd.DB.AutoMigrate(types.Host{})
	pd.DB.AutoMigrate(types.HostStatus{}).AddForeignKey("host_id", "hosts(id)", "RESTRICT", "RESTRICT")
	pd.DB.AutoMigrate(types.HostSgxData{}).AddForeignKey("host_id", "hosts(id)", "RESTRICT", "RESTRICT")
	return nil
}

func (pd *PostgresDatabase) HostRepository() repository.HostRepository {
	return &PostgresHostRepository{db: pd.DB}
}

func (pd *PostgresDatabase) HostStatusRepository() repository.HostStatusRepository {
	return &PostgresHostStatusRepository{db: pd.DB}
}

func (pd *PostgresDatabase) HostSgxDataRepository() repository.HostSgxDataRepository {
	return &PostgresHostSgxDataRepository{db: pd.DB}
}

func (pd *PostgresDatabase) Close() {
	if pd.DB != nil {
		err := pd.DB.Close()
		if err != nil {
			log.WithError(err).Error("failed to close the shvs db")
		}
	}
}

func setConnectionPool(db *gorm.DB) {
	// Query DB's max_connections settings
	type Result struct {
		Setting int
	}
	var result Result

	// Note : pg_setting is specific to postgres
	err := db.Raw("SELECT * FROM pg_settings WHERE name = ?", "max_connections").Scan(&result).Error

	if err == nil && result.Setting > 0 {
		log.Debug("DB maximum connection limit is : ", result.Setting)
		serviceDBConnectionLimit := (result.Setting / 100) * constants.DBMaxConnPercentage
		db.DB().SetMaxIdleConns(serviceDBConnectionLimit)
		db.DB().SetMaxOpenConns(serviceDBConnectionLimit)
		db.DB().SetConnMaxLifetime(constants.DBConnMaxLifetimeMinutes * time.Minute)
	} else {
		// Not fatal.
		log.Info("Unable to retrive DB's max_connection. Using default connection pool params.", err)
	}
}

func Open(host string, port int, dbname, user, password, sslMode, sslCert string) (*PostgresDatabase, error) {
	log.Trace("repository/postgres/pg_database: Open() Entering")
	defer log.Trace("repository/postgres/pg_database: Open() Leaving")

	sslMode = strings.TrimSpace(strings.ToLower(sslMode))
	// Set default SSL Mode to verify-full, this mode provides protection from eavesdropping and MITM attack.
	if sslMode != "allow" && sslMode != "prefer" && sslMode != "require" && sslMode != "verify-ca" {
		sslMode = "verify-full"
	}

	var sslCertParams string
	// In case of verify-ca and verify-full, SSL server certificate needs to be specified as client validates the chain of trust.
	if sslMode == "verify-ca" || sslMode == "verify-full" {
		sslCertParams = " sslrootcert=" + sslCert
	}

	var db *gorm.DB
	var dbErr error
	const numAttempts = 4
	for i := 0; i < numAttempts; i++ {
		const retryTime = 5
		db, dbErr = gorm.Open("postgres", fmt.Sprintf("host=%s port=%d user=%s dbname=%s password=%s sslmode=%s%s",
			host, port, user, dbname, password, sslMode, sslCertParams))
		if dbErr != nil {
			slog.Warningf("Failed to connect to DB, retrying attempt %d/%d", i, numAttempts)
		} else {
			break
		}
		time.Sleep(retryTime * time.Second)
	}
	if dbErr != nil {
		slog.Errorf("%s: Failed to connect to db after %d attempts", commLogMsg.BadConnection, numAttempts)
		return nil, dbErr
	}

	setConnectionPool(db)

	return &PostgresDatabase{DB: db}, nil
}
