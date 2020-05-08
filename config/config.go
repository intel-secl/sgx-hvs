/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package config

import (
	"errors"
	log "github.com/sirupsen/logrus"
	commLog "intel/isecl/lib/common/v2/log"
	errorLog "github.com/pkg/errors"
	"gopkg.in/yaml.v2"
	"intel/isecl/lib/common/v2/setup"
	"intel/isecl/sgx-host-verification-service/constants"
	"os"
	"path"
	"strings"
	"sync"
	"time"
)

var slog = commLog.GetSecurityLogger()

// should move this into lib common, as its duplicated across SHVS and SHVS

// Configuration is the global configuration struct that is marshalled/unmarshaled to a persisted yaml file
// Probably should embed a config generic struct
type Configuration struct {
	configFile string
	Port       int
	CmsTlsCertDigest string
	Postgres   struct {
		DBName   string
		Username string
		Password string
		Hostname string
		Port     int
		SSLMode  string
		SSLCert  string
	}
	LogMaxLength	 int
	LogEnableStdout  bool
	LogLevel         log.Level

	AuthDefender struct {
		MaxAttempts         int
		IntervalMins        int
		LockoutDurationMins int
	}
	SHVS struct {
		User     string
		Password string
	}
	Token struct {
		IncludeKid        bool
		TokenDurationMins int
	}
	CMSBaseUrl             string
	AuthServiceUrl         string
	ScsBaseUrl             string
	SchedulerTimer         int
	SHVSRefreshTimer       int
	SHVSHostInfoExpiryTime int
	Subject struct {
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

var mu sync.Mutex

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

func (c *Configuration) Save() error {
	log.Trace("config/config:Save() Entering")
	defer log.Trace("config/config:Save() Leaving")

	if c.configFile == "" {
		return ErrNoConfigFile
	}
	file, err := os.OpenFile(c.configFile, os.O_RDWR, 0)
	if err != nil {
		// we have an error
		if os.IsNotExist(err) {
			// error is that the config doesnt yet exist, create it
			file, err = os.Create(c.configFile)
			os.Chmod(c.configFile, 0660)
			if err != nil {
				return err
			}
		} else {
			// someother I/O related error
			return err
		}
	}
	defer file.Close()
	return yaml.NewEncoder(file).Encode(c)
}

func (conf *Configuration) SaveConfiguration(c setup.Context) error {
	log.Trace("config/config:SaveConfiguration() Entering")
	defer log.Trace("config/config:SaveConfiguration() Leaving")

	var err error = nil

	tlsCertDigest, err := c.GetenvString(constants.CmsTlsCertDigestEnv, "TLS certificate digest")
	if err == nil && tlsCertDigest != "" {
		conf.CmsTlsCertDigest = tlsCertDigest
	} else if conf.CmsTlsCertDigest == "" {
		commLog.GetDefaultLogger().Error("CMS_TLS_CERT_SHA384 is not defined in environment")
		return errorLog.Wrap(errors.New("CMS_TLS_CERT_SHA384 is not defined in environment"), "SaveConfiguration() ENV variable not found")
	}

	cmsBaseUrl, err := c.GetenvString("CMS_BASE_URL", "CMS Base URL")
	if err == nil && cmsBaseUrl != "" {
		conf.CMSBaseUrl = cmsBaseUrl
	} else if conf.CMSBaseUrl == "" {
		commLog.GetDefaultLogger().Error("CMS_BASE_URL is not defined in environment")
		return errorLog.Wrap(errors.New("CMS_BASE_URL is not defined in environment"), "SaveConfiguration() ENV variable not found")
	}

	aasApiUrl, err := c.GetenvString("AAS_API_URL", "AAS Base URL")
	if err == nil && aasApiUrl != "" {
		conf.AuthServiceUrl = aasApiUrl
	} else if conf.AuthServiceUrl == "" {
		commLog.GetDefaultLogger().Error("AAS_API_URL is not defined in environment")
		return errorLog.Wrap(errors.New("AAS_API_URL is not defined in environment"), "SaveConfiguration() ENV variable not found")
	}

	scsBaseUrl, err := c.GetenvString("SCS_BASE_URL", "SCS Base URL")
	if err == nil && scsBaseUrl != "" {
		conf.ScsBaseUrl = scsBaseUrl
	} else if conf.ScsBaseUrl == "" {
		log.Error("SCS_BASE_URL is not defined in environment")
	}

	shvsAASUser, err := c.GetenvString(constants.SHVS_USER, "SHVS Service Username")
	if err == nil && shvsAASUser != "" {
		conf.SHVS.User = shvsAASUser
	} else if conf.SHVS.User == "" {
		commLog.GetDefaultLogger().Error("SHVS_ADMIN_USERNAME is not defined in environment or configuration file")
		return errorLog.Wrap(err, "SHVS_ADMIN_USERNAME is not defined in environment or configuration file")
	}

	shvsAASPassword, err := c.GetenvSecret(constants.SHVS_PASSWORD, "SHVS Service Password")
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

	tlsKeyPath, err := c.GetenvString("KEY_PATH", "Path of file where TLS key needs to be stored")
	if err == nil && tlsKeyPath != "" {
		conf.TLSKeyFile = tlsKeyPath
	} else if conf.TLSKeyFile == "" {
		conf.TLSKeyFile = constants.DefaultTLSKeyFile
	}

	tlsCertPath, err := c.GetenvString("CERT_PATH", "Path of file/directory where TLS certificate needs to be stored")
	if err == nil && tlsCertPath != "" {
		conf.TLSCertFile = tlsCertPath
	} else if conf.TLSCertFile == "" {
		conf.TLSCertFile = constants.DefaultTLSCertFile
	}

	logLevel, err := c.GetenvString("SHVS_LOGLEVEL", "SHVS Log Level")
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

func Load(path string) *Configuration {
	log.Trace("config/config:Load() Entering")
	defer log.Trace("config/config:Load() Leaving")

	var c Configuration
	file, err := os.Open(path)
	if err == nil {
		defer file.Close()
		yaml.NewDecoder(file).Decode(&c)
	} else {
		// file doesnt exist, create a new blank one
		c.LogLevel = log.InfoLevel
	}

	c.configFile = path
	return &c
}
