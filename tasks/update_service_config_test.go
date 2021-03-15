/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"github.com/sirupsen/logrus"
	"intel/isecl/lib/common/v3/setup"
	"intel/isecl/shvs/v3/config"
	"intel/isecl/shvs/v3/constants"
	"os"
	"strings"

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

func TestServerSetupInvalidAASUrl(t *testing.T) {
	os.Setenv("AAS_API_URL", "abcdefg")
	os.Setenv("SCS_PORT", "9000")
	os.Setenv("SCS_BASE_URL", "http://localhost:8444/scs/v1")
	c := *config.Load("testconfig.yml")
	defer os.Remove("testconfig.yml")

	s := Update_Service_Config{
		Flags:         nil,
		Config:        &c,
		ConsoleWriter: os.Stdout,
	}
	ctx := setup.Context{}
	s.Config.SaveConfiguration("update_service_config", ctx)
	err := s.Run(ctx)
	assert.True(t, strings.Contains(err.Error(), "AAS_API_URL provided is invalid"))
	assert.Equal(t, constants.DefaultHTTPSPort, c.Port)
}

func TestServerSetupInvalidScsServerArg(t *testing.T) {
	os.Setenv("AAS_API_URL", "http://localhost:8444/aas/v1")
	os.Setenv("SCS_PORT", "9000")
	os.Setenv("SCS_BASE_URL", "abc")
	c := *config.Load("testconfig.yml")
	defer os.Remove("testconfig.yml")

	s := Update_Service_Config{
		Flags:         nil,
		Config:        &c,
		ConsoleWriter: os.Stdout,
	}
	ctx := setup.Context{}
	s.Config.SaveConfiguration("update_service_config", ctx)
	err := s.Run(ctx)
	assert.True(t, strings.Contains(err.Error(), "SCS_BASE_URL provided is invalid"))
	assert.Equal(t, constants.DefaultHTTPSPort, c.Port)
}

func TestServerSetupInvalidLogLevelArg(t *testing.T) {
	os.Setenv("AAS_API_URL", "http://localhost:8444/aas/v1")
	os.Setenv("SCS_PORT", "9000")
	os.Setenv("SCS_BASE_URL", "http://localhost:8444/ips")
	os.Setenv("LOG_LEVEL", "invalidloglevel")
	c := *config.Load("testconfig.yml")
	defer os.Remove("testconfig.yml")

	s := Update_Service_Config{
		Flags:         nil,
		Config:        &c,
		ConsoleWriter: os.Stdout,
	}
	ctx := setup.Context{}
	s.Config.SaveConfiguration("update_service_config", ctx)
	err := s.Run(ctx)
	assert.NoError(t, err)
	assert.Equal(t, logrus.InfoLevel, c.LogLevel)
}
