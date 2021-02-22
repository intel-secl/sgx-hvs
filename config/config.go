/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package config

import (
	"errors"
	errorLog "github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
	commLog "intel/isecl/lib/common/v3/log"
	"intel/isecl/lib/common/v3/setup"
	"intel/isecl/shvs/v3/constants"
	"os"
	"path"
	"strings"
	"time"
)

var slog = commLog.GetSecurityLogger()

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
	LogLevel        log.Level

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

func (conf *Configuration) SaveConfiguration(c setup.Context) error {
	log.Trace("config/config:SaveConfiguration() Entering")
	defer log.Trace("config/config:SaveConfiguration() Leaving")

	var err error = nil

	tlsCertDigest, err := c.GetenvString("CMS_TLS_CERT_SHA384", "TLS certificate digest")
	if err == nil && tlsCertDigest != "" {
		conf.CmsTLSCertDigest = tlsCertDigest
	} else if conf.CmsTLSCertDigest == "" {
		commLog.GetDefaultLogger().Error("CMS_TLS_CERT_SHA384 is not defined in environment")
		return errorLog.Wrap(errors.New("CMS_TLS_CERT_SHA384 is not defined in environment"), "SaveConfiguration() ENV variable not found")
	}

	cmsBaseURL, err := c.GetenvString("CMS_BASE_URL", "CMS Base URL")
	if err == nil && cmsBaseURL != "" {
		conf.CMSBaseURL = cmsBaseURL
	} else if conf.CMSBaseURL == "" {
		commLog.GetDefaultLogger().Error("CMS_BASE_URL is not defined in environment")
		return errorLog.Wrap(errors.New("CMS_BASE_URL is not defined in environment"), "SaveConfiguration() ENV variable not found")
	}

	aasAPIURL, err := c.GetenvString("AAS_API_URL", "AAS Base URL")
	if err == nil && aasAPIURL != "" {
		conf.AuthServiceURL = aasAPIURL
	} else if conf.AuthServiceURL == "" {
		commLog.GetDefaultLogger().Error("AAS_API_URL is not defined in environment")
		return errorLog.Wrap(errors.New("AAS_API_URL is not defined in environment"), "SaveConfiguration() ENV variable not found")
	}

	scsBaseURL, err := c.GetenvString("SCS_BASE_URL", "SCS Base URL")
	if err == nil && scsBaseURL != "" {
		conf.ScsBaseURL = scsBaseURL
	} else if conf.ScsBaseURL == "" {
		log.Error("SCS_BASE_URL is not defined in environment")
	}

	shvsAASUser, err := c.GetenvString("SHVS_ADMIN_USERNAME", "SHVS Service Username")
	if err == nil && shvsAASUser != "" {
		conf.SHVS.User = shvsAASUser
	} else if conf.SHVS.User == "" {
		commLog.GetDefaultLogger().Error("SHVS_ADMIN_USERNAME is not defined in environment or configuration file")
		return errorLog.Wrap(err, "SHVS_ADMIN_USERNAME is not defined in environment or configuration file")
	}

	shvsAASPassword, err := c.GetenvSecret("SHVS_ADMIN_PASSWORD", "SHVS Service Password")
	if err == nil && shvsAASPassword != "" {
		conf.SHVS.Password = shvsAASPassword
	} else if strings.TrimSpace(conf.SHVS.Password) == "" {
		commLog.GetDefaultLogger().Error("SHVS_ADMIN_PASSWORD is not defined in environment or configuration file")
		return errorLog.Wrap(err, "SHVS_ADMIN_PASSWORD is not defined in environment or configuration file")
	}

	tlsCertCN, err := c.GetenvString("SHVS_TLS_CERT_CN", "SHVS TLS Certificate Common Name")
	if err == nil && tlsCertCN != "" {
		conf.Subject.TLSCertCommonName = tlsCertCN
	} else if conf.Subject.TLSCertCommonName == "" {
		conf.Subject.TLSCertCommonName = constants.DefaultSHVSTlsCn
	}

	tlsKeyPath, err := c.GetenvString("KEY_PATH", "Filepath where TLS key needs to be stored")
	if err == nil && tlsKeyPath != "" {
		conf.TLSKeyFile = tlsKeyPath
	} else if conf.TLSKeyFile == "" {
		conf.TLSKeyFile = constants.DefaultTLSKeyFile
	}

	tlsCertPath, err := c.GetenvString("CERT_PATH", "Filepath where TLS certificate needs to be stored")
	if err == nil && tlsCertPath != "" {
		conf.TLSCertFile = tlsCertPath
	} else if conf.TLSCertFile == "" {
		conf.TLSCertFile = constants.DefaultTLSCertFile
	}

	logLevel, err := c.GetenvString(constants.SHVSLogLevel, "SHVS Log Level")
	if err != nil {
		slog.Infof("config/config:SaveConfiguration() %s not defined, using default log level: Info", constants.SHVSLogLevel)
		conf.LogLevel = log.InfoLevel
	} else {
		llp, err := log.ParseLevel(logLevel)
		if err != nil {
			slog.Info("config/config:SaveConfiguration() Invalid log level specified in env, using default log level: Info")
			conf.LogLevel = log.InfoLevel
		} else {
			conf.LogLevel = llp
			slog.Infof("config/config:SaveConfiguration() Log level set %s\n", logLevel)
		}
	}

	sanList, err := c.GetenvString("SAN_LIST", "SAN list for TLS")
	if err == nil && sanList != "" {
		conf.CertSANList = sanList
	} else if conf.CertSANList == "" {
		conf.CertSANList = constants.DefaultSHVSTlsSan
	}

	schedulerTimeout, err := c.GetenvInt("SHVS_SCHEDULER_TIMER", "SHVS Scheduler Timeout Seconds")
	if err == nil && schedulerTimeout != 0 {
		conf.SchedulerTimer = schedulerTimeout
	} else if conf.SchedulerTimer == 0 {
		conf.SchedulerTimer = constants.DefaultSHVSSchedulerTimer
	}

	autoRefreshTimeout, err := c.GetenvInt("SHVS_AUTO_REFRESH_TIMER", "SHVS autoRefresh Timeout Seconds")
	if err == nil && autoRefreshTimeout != 0 {
		conf.SHVSRefreshTimer = autoRefreshTimeout
	} else if conf.SHVSRefreshTimer == 0 {
		conf.SHVSRefreshTimer = constants.DefaultSHVSAutoRefreshTimer
	}

	hostPlatformInfoexpiryTime, err := c.GetenvInt("SHVS_HOST_PLATFORM_EXPIRY_TIME", "SHVS autoRefresh Timeout Seconds")
	if err == nil && hostPlatformInfoexpiryTime != 0 {
		conf.SHVSHostInfoExpiryTime = hostPlatformInfoexpiryTime
	} else if conf.SHVSHostInfoExpiryTime == 0 {
		conf.SHVSHostInfoExpiryTime = constants.DefaultSHVSHostInfoExpiryTime
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
		c.LogLevel = log.InfoLevel
	}
	c.configFile = filePath
	return &c
}
