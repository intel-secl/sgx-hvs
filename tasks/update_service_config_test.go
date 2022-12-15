/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"intel/isecl/lib/common/v5/setup"
	"intel/isecl/shvs/v5/config"
	"intel/isecl/shvs/v5/constants"
	"math/rand"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestServerSetup(t *testing.T) {
	os.Setenv("SHVS_ADMIN_USERNAME", RandStringBytes())
	os.Setenv("SHVS_ADMIN_PASSWORD", RandStringBytes())
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
	os.Setenv("SHVS_ADMIN_USERNAME", RandStringBytes())
	os.Setenv("SHVS_ADMIN_PASSWORD", RandStringBytes())
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

	// Negative tests.

	invalidPortSetupEnv := Update_Service_Config{
		Flags:         []string{"-port=137"},
		Config:        &c,
		ConsoleWriter: os.Stdout,
	}
	err = invalidPortSetupEnv.Run(ctx)
	assert.Equal(t, err, nil)

	os.Setenv("SHVS_SERVER_READ_TIMEOUT", "testvalue")
	os.Setenv("SHVS_SERVER_READ_HEADER_TIMEOUT", "testvalue")
	os.Setenv("SHVS_SERVER_WRITE_TIMEOUT", "testvalue")
	os.Setenv("SHVS_SERVER_IDLE_TIMEOUT", "testvalue")
	os.Setenv("SHVS_SERVER_MAX_HEADER_BYTES", "1500")
	err = s.Run(ctx)
	assert.NotEqual(t, err, nil)

	// Empty AAS URL
	emptyAAS := config.Configuration{
		AuthServiceURL: "",
	}
	emptyAASService := Update_Service_Config{
		Flags:         []string{"-port=1337"},
		Config:        &emptyAAS,
		ConsoleWriter: os.Stdout,
	}
	err = emptyAASService.Run(ctx)
	assert.NotEqual(t, err, nil)

	// Empty SCS URL
	emptySCS := config.Configuration{
		AuthServiceURL: "https://localhost",
		ScsBaseURL:     "",
	}
	emptySCSService := Update_Service_Config{
		Flags:         []string{"-port=1337"},
		Config:        &emptySCS,
		ConsoleWriter: os.Stdout,
	}
	err = emptySCSService.Run(ctx)
	assert.NotEqual(t, err, nil)

	os.Unsetenv("SHVS_ADMIN_USERNAME")
	os.Unsetenv("SHVS_ADMIN_PASSWORD")

	// Empty SHVS_ADMIN_USERNAME
	emptyAdminName := config.Configuration{
		AuthServiceURL: "https://localhost",
		ScsBaseURL:     "https://localhost",
		SHVS: struct {
			User     string
			Password string
		}{
			User: "",
		},
	}
	emptyAdminNameService := Update_Service_Config{
		Flags:         []string{"-port=1337"},
		Config:        &emptyAdminName,
		ConsoleWriter: os.Stdout,
	}
	err = emptyAdminNameService.Run(ctx)
	assert.NotEqual(t, err, nil)

	// Empty SHVS_ADMIN_PASSWORD
	emptyAdminPassword := config.Configuration{
		AuthServiceURL: "https://localhost",
		ScsBaseURL:     "https://localhost",
		SHVS: struct {
			User     string
			Password string
		}{
			User:     RandStringBytes(),
			Password: "",
		},
	}
	emptyAdminPassService := Update_Service_Config{
		Flags:         []string{"-port=1337"},
		Config:        &emptyAdminPassword,
		ConsoleWriter: os.Stdout,
	}
	err = emptyAdminPassService.Run(ctx)
	assert.NotEqual(t, err, nil)

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

	err = s.Validate(ctx)
	assert.Equal(t, err, nil)
}

func TestServerSetupInvalidLogLevelArg(t *testing.T) {
	os.Setenv("AAS_API_URL", "http://localhost:8444/aas/v1")
	os.Setenv("SCS_PORT", "9000")
	os.Setenv("SCS_BASE_URL", "http://localhost:8444/ips")
	os.Setenv("LOG_LEVEL", "invalidloglevel")
	os.Setenv("SHVS_ADMIN_USERNAME", RandStringBytes())
	os.Setenv("SHVS_ADMIN_PASSWORD", RandStringBytes())
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

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

func RandStringBytes() string {
	rand.Seed(time.Now().UnixNano())
	b := make([]byte, 10)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return string(b)
}
