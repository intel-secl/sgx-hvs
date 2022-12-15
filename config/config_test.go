/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package config

import (
	"intel/isecl/lib/common/v5/setup"
	"io/ioutil"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLoad(t *testing.T) {
	temp, _ := ioutil.TempFile("", "config.yml")
	temp.WriteString("port: 1337\naas:\n")
	defer os.Remove(temp.Name())
	c := Load(temp.Name())
	assert.Equal(t, 1337, c.Port)
}

func TestSave(t *testing.T) {
	temp, _ := ioutil.TempFile("", "config.yml")
	defer os.Remove(temp.Name())
	c := Load(temp.Name())
	c.Port = 1337
	c.Save()
	c2 := Load(temp.Name())
	assert.Equal(t, 1337, c2.Port)

	// Empty config file path given
	emptyConf := &Configuration{
		configFile: "",
		Port:       1337,
	}

	err := emptyConf.Save()
	assert.NotEqual(t, err, nil)

	// Invalid file path given
	invalidConf := &Configuration{
		configFile: "/invalid/path/",
		Port:       1337,
	}
	err = invalidConf.Save()
	assert.NotEqual(t, err, nil)
}

func TestGlobal(t *testing.T) {
	global = Global()
	assert.NotEmpty(t, global)
}

func TestSaveConfiguration(t *testing.T) {
	temp, _ := ioutil.TempFile("", "config.yml")
	defer os.Remove(temp.Name())
	c := Load(temp.Name())
	c.Port = 1337
	var ctx setup.Context
	err := c.SaveConfiguration("all", ctx)
	assert.NotEmpty(t, err)

	c.CmsTLSCertDigest = "abcdefghijklmnopqrstuvwxyz1234567890"

	c.CMSBaseURL = ""
	err = c.SaveConfiguration("all", ctx)
	assert.NotEmpty(t, err)

	c.CMSBaseURL = "https://cms.com/cms/v1"
	err = c.SaveConfiguration("all", ctx)
	assert.Empty(t, err)

	// Read from env.
	os.Setenv("CMS_TLS_CERT_SHA384", "abcdefghijklmnopqrstuvwxyz1234567890")
	os.Setenv("CMS_BASE_URL", "https://cms.com/cms/v1")
	os.Setenv("SHVS_TLS_CERT_CN", "TEST COMMON NAME")
	os.Setenv("KEY_PATH", "test/tls.key")
	os.Setenv("CERT_PATH", "test/tls-cert.pem")
	os.Setenv("SAN_LIST", "test")
	err = c.SaveConfiguration("all", ctx)
	assert.Empty(t, err)

	os.Setenv("CMS_BASE_URL", "https://cms.com/cms/v1%+o")
	err = c.SaveConfiguration("all", ctx)
	assert.NotEmpty(t, err)
}
