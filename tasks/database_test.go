/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"intel/isecl/lib/common/v3/setup"
	"intel/isecl/shvs/v3/config"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDatabaseSetup(t *testing.T) {
	assert := assert.New(t)
	c := config.Configuration{}
	s := Database{
		Flags:         []string{"-db-host=hostname", "-db-port=5432", "-db-user=user", "-db-pass=password", "-db-name=scs_db"},
		Config:        &c,
		ConsoleWriter: os.Stdout,
	}
	ctx := setup.Context{}
	err := s.Run(ctx)
	assert.Error(err)
	assert.Equal("hostname", c.Postgres.Hostname)
	assert.Equal(5432, c.Postgres.Port)
	assert.Equal("user", c.Postgres.Username)
	assert.Equal("password", c.Postgres.Password)
	assert.Equal("scs_db", c.Postgres.DBName)
}

func TestDatabaseSetupEnv(t *testing.T) {
	assert := assert.New(t)
	os.Setenv("SHVS_DB_HOSTNAME", "hostname")
	os.Setenv("SHVS_DB_PORT", "5432")
	os.Setenv("SHVS_DB_USERNAME", "user")
	os.Setenv("SHVS_DB_PASSWORD", "password")
	os.Setenv("SHVS_DB_NAME", "scs_db")
	c := config.Configuration{}
	s := Database{
		Flags:         nil,
		Config:        &c,
		ConsoleWriter: os.Stdout,
	}
	ctx := setup.Context{}
	err := s.Run(ctx)
	assert.Error(err)
	assert.Equal("hostname", c.Postgres.Hostname)
	assert.Equal(5432, c.Postgres.Port)
	assert.Equal("user", c.Postgres.Username)
	assert.Equal("password", c.Postgres.Password)
	assert.Equal("scs_db", c.Postgres.DBName)
}
