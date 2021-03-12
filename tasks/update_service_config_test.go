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

func TestServerSetup(t *testing.T) {
	os.Setenv("SHVS_ADMIN_USERNAME", "shvsuser")
	os.Setenv("SHVS_ADMIN_PASSWORD", "shvspassword")
	c := config.Configuration{
		AuthServiceURL: "https://localhost",
		ScsBaseURL:     "https://localhost",
	}
	s := Update_Service_Config{
		Flags:         []string{"-port=1337"},
		Config:        &c,
		ConsoleWriter: os.Stdout,
	}
	ctx := setup.Context{}
	err := s.Run(ctx)
	if err != nil {
		assert.Contains(t, err.Error(), config.ErrNoConfigFile.Error())
	}
	assert.Equal(t, 1337, c.Port)
}

func TestServerSetupEnv(t *testing.T) {
	os.Setenv("SHVS_ADMIN_USERNAME", "shvsuser")
	os.Setenv("SHVS_ADMIN_PASSWORD", "shvspassword")
	c := config.Configuration{
		AuthServiceURL: "https://localhost",
		ScsBaseURL:     "https://localhost",
	}
	s := Update_Service_Config{
		Flags:         []string{"-port=1337"},
		Config:        &c,
		ConsoleWriter: os.Stdout,
	}
	ctx := setup.Context{}
	err := s.Run(ctx)
	if err != nil {
		assert.Contains(t, err.Error(), config.ErrNoConfigFile.Error())
	}
	assert.Equal(t, 1337, c.Port)
}
