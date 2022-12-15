/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package config

import (
	"errors"
	errorLog "github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
	commLog "intel/isecl/lib/common/v5/log"
	"intel/isecl/lib/common/v5/setup"
	"intel/isecl/shvs/v5/constants"
	"net/url"
	"os"
	"path"
	"strings"
	"time"
)

var log = commLog.GetDefaultLogger()

// Configuration is the global configuration struct that is marshalled/unmarshaled to a persisted yaml file
type Configuration struct {
	configFile       string
	Port             int
	CmsTLSCertDigest string
	Postgres         struct {
		DBName   string
		Username string
		Password string
		Hostname string
		Port     int
		SSLMode  string
		SSLCert  string
	}
	LogMaxLength    int
	LogEnableStdout bool
	LogLevel        logrus.Level

	SHVS struct {
		User     string
		Password string
	}
	Token struct {
		IncludeKid        bool
		TokenDurationMins int
	}
	CMSBaseURL             string
	AuthServiceURL         string
	ScsBaseURL             string
	SchedulerTimer         int
	SHVSRefreshTimer       int
	SHVSHostInfoExpiryTime int
	Subject                struct {
		TLSCertCommonName string
	}
	TLSKeyFile        string
	TLSCertFile       string
	CertSANList       string
	ReadTimeout       time.Duration
	ReadHeaderTimeout time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration
	MaxHeaderBytes    int
}

var global *Configuration

func Global() *Configuration {
	log.Trace("config/config:Global() Entering")
	defer log.Trace("config/config:Global() Leaving")

	if global == nil {
		global = Load(path.Join(constants.ConfigDir, constants.ConfigFile))
	}
	return global
}

var ErrNoConfigFile = errors.New("no config file")

func (conf *Configuration) Save() error {
	log.Trace("config/config:Save() Entering")
	defer log.Trace("config/config:Save() Leaving")

	if conf.configFile == "" {
		return ErrNoConfigFile
	}
	file, err := os.OpenFile(conf.configFile, os.O_RDWR, 0)
	if err != nil {
		// we have an error
		if os.IsNotExist(err) {
			// error is that the config doesn't yet exist, create it
			file, err = os.OpenFile(conf.configFile, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
			if err != nil {
				return err
			}
		} else {
			// some other I/O related error
			return err
		}
	}
	defer func() {
		derr := file.Close()
		if derr != nil {
			log.WithError(derr).Error("Failed to flush config.yml")
		}
	}()

	return yaml.NewEncoder(file).Encode(conf)
}

func (conf *Configuration) SaveConfiguration(taskName string, c setup.Context) error {
	log.Trace("config/config:SaveConfiguration() Entering")
	defer log.Trace("config/config:SaveConfiguration() Leaving")

	// target config changes only in scope for the setup task
	if taskName == "all" || taskName == "download_ca_cert" || taskName == "download_cert" {
		tlsCertDigest, err := c.GetenvString("CMS_TLS_CERT_SHA384", "TLS certificate digest")
		if err == nil && strings.TrimSpace(tlsCertDigest) != "" {
			conf.CmsTLSCertDigest = tlsCertDigest
		} else if conf.CmsTLSCertDigest == "" {
			log.Error("CMS_TLS_CERT_SHA384 is not defined in environment")
			return errorLog.Wrap(errors.New("CMS_TLS_CERT_SHA384 is not defined in environment"), "SaveConfiguration() ENV variable not found")
		}

		cmsBaseURL, err := c.GetenvString("CMS_BASE_URL", "CMS Base URL")
		if err == nil && strings.TrimSpace(cmsBaseURL) != "" {
			if _, err = url.ParseRequestURI(cmsBaseURL); err != nil {
				log.Error("CMS_BASE_URL provided is invalid")
				return errorLog.Wrap(err, "SaveConfiguration() CMS_BASE_URL provided is invalid")
			}
			conf.CMSBaseURL = cmsBaseURL
		} else if conf.CMSBaseURL == "" {
			log.Error("CMS_BASE_URL is not defined in environment")
			return errorLog.Wrap(errors.New("CMS_BASE_URL is not defined in environment"),
				"SaveConfiguration() ENV variable not found")
		}
	}

	if taskName == "all" || taskName == "download_cert" {
		tlsCertCN, err := c.GetenvString("SHVS_TLS_CERT_CN", "SHVS TLS Certificate Common Name")
		if err == nil && strings.TrimSpace(tlsCertCN) != "" {
			conf.Subject.TLSCertCommonName = tlsCertCN
		} else if conf.Subject.TLSCertCommonName == "" {
			conf.Subject.TLSCertCommonName = constants.DefaultSHVSTlsCn
		}

		tlsKeyPath, err := c.GetenvString("KEY_PATH", "Filepath where TLS key needs to be stored")
		if err == nil && strings.TrimSpace(tlsKeyPath) != "" {
			conf.TLSKeyFile = tlsKeyPath
		} else if conf.TLSKeyFile == "" {
			conf.TLSKeyFile = constants.DefaultTLSKeyFile
		}

		tlsCertPath, err := c.GetenvString("CERT_PATH", "Filepath where TLS certificate needs to be stored")
		if err == nil && strings.TrimSpace(tlsCertPath) != "" {
			conf.TLSCertFile = tlsCertPath
		} else if conf.TLSCertFile == "" {
			conf.TLSCertFile = constants.DefaultTLSCertFile
		}

		sanList, err := c.GetenvString("SAN_LIST", "SAN list for TLS")
		if err == nil && strings.TrimSpace(sanList) != "" {
			conf.CertSANList = sanList
		} else if conf.CertSANList == "" {
			conf.CertSANList = constants.DefaultSHVSTlsSan
		}
	}

	return conf.Save()
}

func Load(filePath string) *Configuration {
	log.Trace("config/config:Load() Entering")
	defer log.Trace("config/config:Load() Leaving")

	var c Configuration
	file, _ := os.Open(filePath)
	if file != nil {
		defer func() {
			derr := file.Close()
			if derr != nil {
				log.WithError(derr).Error("Failed to close config.yml")
			}
		}()
		err := yaml.NewDecoder(file).Decode(&c)
		if err != nil {
			log.WithError(err).Error("Failed to decode config.yml contents")
		}
	} else {
		c.LogLevel = logrus.InfoLevel
	}
	c.configFile = filePath
	return &c
}
