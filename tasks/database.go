/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	//"errors"
	"flag"
	"fmt"
	"github.com/pkg/errors"
	commLog "intel/isecl/lib/common/v3/log"
	commLogMsg "intel/isecl/lib/common/v3/log/message"
	cos "intel/isecl/lib/common/v3/os"
	"intel/isecl/lib/common/v3/setup"
	"intel/isecl/lib/common/v3/validation"
	"intel/isecl/shvs/v3/config"
	"intel/isecl/shvs/v3/constants"
	"intel/isecl/shvs/v3/repository/postgres"
	"io"
	"os"
	"strings"
)

var slog = commLog.GetSecurityLogger()

type Database struct {
	Flags         []string
	Config        *config.Configuration
	ConsoleWriter io.Writer
}

func (db Database) Run(c setup.Context) error {
	fmt.Fprintln(db.ConsoleWriter, "Running database setup...")
	envHost, _ := c.GetenvString("SHVS_DB_HOSTNAME", "Database Hostname")
	envPort, _ := c.GetenvInt("SHVS_DB_PORT", "Database Port")
	envUser, _ := c.GetenvString("SHVS_DB_USERNAME", "Database Username")
	envPass, _ := c.GetenvSecret("SHVS_DB_PASSWORD", "Database Password")
	envDB, _ := c.GetenvString("SHVS_DB_NAME", "Database Name")
	envDBSSLMode, _ := c.GetenvString("SHVS_DB_SSLMODE", "Database SSLMode")
	envDBSSLCert, _ := c.GetenvString("SHVS_DB_SSLCERT", "Database SSL Certificate")
	envDBSSLCertSrc, _ := c.GetenvString("SHVS_DB_SSLCERTSRC", "Database SSL Cert file source file")

	fs := flag.NewFlagSet("database", flag.ContinueOnError)
	fs.StringVar(&db.Config.Postgres.Hostname, "db-host", envHost, "Database Hostname")
	fs.IntVar(&db.Config.Postgres.Port, "db-port", envPort, "Database Port")
	fs.StringVar(&db.Config.Postgres.Username, "db-user", envUser, "Database Username")
	fs.StringVar(&db.Config.Postgres.Password, "db-pass", envPass, "Database Password")
	fs.StringVar(&db.Config.Postgres.DBName, "db-name", envDB, "Database Name")
	fs.StringVar(&db.Config.Postgres.SSLMode, "db-sslmode", envDBSSLMode, "SSL mode of connection to database")
	fs.StringVar(&db.Config.Postgres.SSLCert, "db-sslcert", envDBSSLCert, "SSL certificate of database")
	fs.StringVar(&envDBSSLCertSrc, "db-sslcertsrc", envDBSSLCertSrc, "DB SSL certificate to be copied from")
	err := fs.Parse(db.Flags)
	if err != nil {
		return errors.Wrap(err, "setup database: failed to parse cmd flags")
	}

	var valid_err error

	valid_err = validation.ValidateHostname(db.Config.Postgres.Hostname)
	if valid_err != nil {
		slog.Errorf("%s: Failed to connect to db, Input validation failed for database hostname", commLogMsg.BadConnection)
		return valid_err
	}
	valid_err = validation.ValidateAccount(db.Config.Postgres.Username, db.Config.Postgres.Password)
	if valid_err != nil {
		slog.Errorf("%s: Failed to connect to db, Input validation failed for database credentials", commLogMsg.BadConnection)
		return valid_err
	}
	valid_err = validation.ValidateIdentifier(db.Config.Postgres.DBName)
	if valid_err != nil {
		slog.Errorf("%s: Failed to connect to db, Input validation failed for database name", commLogMsg.BadConnection)
		return valid_err
	}

	// Configure database SSL parameters such as SSL Mode and SSL Certificate filepath
	db.Config.Postgres.SSLMode, db.Config.Postgres.SSLCert, valid_err = configureDBSSLParams(
		db.Config.Postgres.SSLMode, envDBSSLCertSrc,
		db.Config.Postgres.SSLCert)
	if valid_err != nil {
		slog.Errorf("%s: Failed to connect to db, Input validation failed for database SSL parameters", commLogMsg.BadConnection)
		return valid_err
	}

	// Open connection to the postgres database
	pg := db.Config.Postgres
	p, err := postgres.Open(pg.Hostname, pg.Port, pg.DBName, pg.Username, pg.Password, pg.SSLMode, pg.SSLCert)
	if err != nil {
		return errors.Wrap(err, "setup database: failed to open database")
	}
	err = p.Migrate()
	if err != nil {
		log.WithError(err).Error("Failed to migrate database")
	}

	err = db.Config.Save()
	if err != nil {
		return errors.Wrap(err, "setup database: failed to save config")
	}
	return nil
}

func configureDBSSLParams(sslMode, sslCertSrc, sslCert string) (string, string, error) {
	sslMode = strings.TrimSpace(strings.ToLower(sslMode))
	sslCert = strings.TrimSpace(sslCert)
	sslCertSrc = strings.TrimSpace(sslCertSrc)

	if sslMode != "allow" && sslMode != "prefer" && sslMode != "require" && sslMode != "verify-ca" {
		sslMode = "verify-full"
	}

	if sslMode == "verify-ca" || sslMode == "verify-full" {
		// cover different scenarios
		if sslCertSrc == "" && sslCert != "" {
			if _, err := os.Stat(sslCert); os.IsNotExist(err) {
				return "", "", errors.Wrapf(err, "certificate source file not specified and sslcert %s does not exist", sslCert)
			}
			return sslMode, sslCert, nil
		}
		if sslCertSrc == "" {
			return "", "", errors.New("verify-ca or verify-full needs a source cert file to copy from unless db-sslcert exists")
		} else {
			if _, err := os.Stat(sslCertSrc); os.IsNotExist(err) {
				return "", "", errors.Wrapf(err, "certificate source file not specified and sslcert %s does not exist", sslCertSrc)
			}
		}
		// at this point if sslCert destination is not passed it, lets set to default
		if sslCert == "" {
			sslCert = constants.DefaultSSLCertFilePath
		}
		// lets try to copy the file now. If copy does not succeed return the file copy error
		if err := cos.Copy(sslCertSrc, sslCert); err != nil {
			return "", "", errors.Wrap(err, "failed to copy file")
		}
		// set permissions so that non root users can read the copied file
		if err := os.Chmod(sslCert, 0644); err != nil {
			return "", "", errors.Wrapf(err, "could not apply permissions to %s", sslCert)
		}
	}
	return sslMode, sslCert, nil
}

func (db Database) Validate(c setup.Context) error {
	if db.Config.Postgres.Hostname == "" {
		return errors.New("database setup: Hostname is not set")
	}
	if db.Config.Postgres.Port == 0 {
		return errors.New("database setup: Port is not set")
	}
	if db.Config.Postgres.Username == "" {
		return errors.New("database setup: Username is not set")
	}
	if db.Config.Postgres.Password == "" {
		return errors.New("database setup: Password is not set")
	}
	if db.Config.Postgres.DBName == "" {
		return errors.New("database: Schema is not set")
	}
	return nil
}
