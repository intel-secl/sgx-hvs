/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"flag"
	"fmt"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	commLog "intel/isecl/lib/common/v3/log"
	"intel/isecl/lib/common/v3/setup"
	"intel/isecl/shvs/v3/config"
	"intel/isecl/shvs/v3/constants"
	"io"
	"net/url"
	"strings"
	"time"
)

type Update_Service_Config struct {
	Flags         []string
	Config        *config.Configuration
	ConsoleWriter io.Writer
}

var log = commLog.GetDefaultLogger()

func (s Update_Service_Config) Run(c setup.Context) error {
	log.Trace("tasks/server:Run() Entering")
	defer log.Trace("tasks/server:Run() Leaving")

	fmt.Fprintln(s.ConsoleWriter, "Running server setup...")
	defaultPort, err := c.GetenvInt("SHVS_PORT", "SGX Host Verification secure port")
	if err != nil {
		defaultPort = constants.DefaultHTTPSPort
	}
	fs := flag.NewFlagSet("server", flag.ContinueOnError)

	fs.IntVar(&s.Config.Port, "port", defaultPort, "SGX Host Verification secure port")
	err = fs.Parse(s.Flags)
	if err != nil {
		return errors.Wrap(err, "tasks/server:Run() Could not parse input flags")
	}
	if s.Config.Port > 65535 || s.Config.Port <= 1024 {
		return errors.Wrap(err, "tasks/server:Run() Invalid or reserved port")
	}
	fmt.Fprintf(s.ConsoleWriter, "Using HTTPS port: %d\n", s.Config.Port)

	readTimeout, err := c.GetenvString("SHVS_SERVER_READ_TIMEOUT", "SGX Host Verification Service Read Timeout")
	if err != nil {
		s.Config.ReadTimeout = constants.DefaultReadTimeout
	} else {
		s.Config.ReadTimeout, err = time.ParseDuration(readTimeout)
		if err != nil {
			fmt.Fprintf(s.ConsoleWriter, "Invalid duration provided for SHVS_SERVER_READ_TIMEOUT setting it to the default value\n")
			s.Config.ReadTimeout = constants.DefaultReadTimeout
		}
	}

	readHeaderTimeout, err := c.GetenvString("SHVS_SERVER_READ_HEADER_TIMEOUT", "SGX Host Verification Service Read Header Timeout")
	if err != nil {
		s.Config.ReadHeaderTimeout = constants.DefaultReadHeaderTimeout
	} else {
		s.Config.ReadHeaderTimeout, err = time.ParseDuration(readHeaderTimeout)
		if err != nil {
			fmt.Fprintf(s.ConsoleWriter, "Invalid duration provided for SHVS_SERVER_READ_HEADER_TIMEOUT setting it to the default value\n")
			s.Config.ReadHeaderTimeout = constants.DefaultReadHeaderTimeout
		}
	}

	writeTimeout, err := c.GetenvString("SHVS_SERVER_WRITE_TIMEOUT", "SGX Host Verification Service Write Timeout")
	if err != nil {
		s.Config.WriteTimeout = constants.DefaultWriteTimeout
	} else {
		s.Config.WriteTimeout, err = time.ParseDuration(writeTimeout)
		if err != nil {
			fmt.Fprintf(s.ConsoleWriter, "Invalid duration provided for SHVS_SERVER_WRITE_TIMEOUT setting it to the default value\n")
			s.Config.WriteTimeout = constants.DefaultWriteTimeout
		}
	}

	idleTimeout, err := c.GetenvString("SHVS_SERVER_IDLE_TIMEOUT", "SGX Host Verification Service Service Idle Timeout")
	if err != nil {
		s.Config.IdleTimeout = constants.DefaultIdleTimeout
	} else {
		s.Config.IdleTimeout, err = time.ParseDuration(idleTimeout)
		if err != nil {
			fmt.Fprintf(s.ConsoleWriter, "Invalid duration provided for SHVS_SERVER_IDLE_TIMEOUT setting it to the default value\n")
			s.Config.IdleTimeout = constants.DefaultIdleTimeout
		}
	}

	maxHeaderBytes, err := c.GetenvInt("SHVS_SERVER_MAX_HEADER_BYTES", "SGX Host Verification Service Max Header Bytes Timeout")
	if err != nil {
		s.Config.MaxHeaderBytes = constants.DefaultMaxHeaderBytes
	} else {
		s.Config.MaxHeaderBytes = maxHeaderBytes
	}

	aasAPIURL, err := c.GetenvString("AAS_API_URL", "AAS Base URL")
	if err == nil && aasAPIURL != "" {
		if _, err = url.Parse(aasAPIURL); err != nil {
			return errors.Wrap(err, "SaveConfiguration() AAS_API_URL provided is invalid")
		} else {
			s.Config.AuthServiceURL = aasAPIURL
		}
	} else if s.Config.AuthServiceURL == "" {
		log.Error("AAS_API_URL is not defined in environment")
		return errors.Wrap(errors.New("AAS_API_URL is not defined in environment"), "SaveConfiguration() ENV variable not found")
	}

	scsBaseURL, err := c.GetenvString("SCS_BASE_URL", "SCS Base URL")
	if err == nil && scsBaseURL != "" {
		if _, err = url.Parse(scsBaseURL); err != nil {
			return errors.Wrap(err, "SaveConfiguration() SCS_BASE_URL provided is invalid")
		} else {
			s.Config.ScsBaseURL = scsBaseURL
		}
	} else if s.Config.ScsBaseURL == "" {
		log.Error("SCS_BASE_URL is not defined in environment")
		return errors.Wrap(errors.New("SCS_BASE_URL is not defined in environment"), "SaveConfiguration() ENV variable not found")
	}

	shvsAASUser, err := c.GetenvString("SHVS_ADMIN_USERNAME", "SHVS Service Username")
	if err == nil && shvsAASUser != "" {
		s.Config.SHVS.User = shvsAASUser
	} else if s.Config.SHVS.User == "" {
		log.Error("SHVS_ADMIN_USERNAME is not defined in environment or configuration file")
		return errors.Wrap(err, "SHVS_ADMIN_USERNAME is not defined in environment or configuration file")
	}

	shvsAASPassword, err := c.GetenvSecret("SHVS_ADMIN_PASSWORD", "SHVS Service Password")
	if err == nil && shvsAASPassword != "" {
		s.Config.SHVS.Password = shvsAASPassword
	} else if strings.TrimSpace(s.Config.SHVS.Password) == "" {
		log.Error("SHVS_ADMIN_PASSWORD is not defined in environment or configuration file")
		return errors.Wrap(err, "SHVS_ADMIN_PASSWORD is not defined in environment or configuration file")
	}

	schedulerTimeout, err := c.GetenvInt("SHVS_SCHEDULER_TIMER", "SHVS Scheduler Timeout Seconds")
	if err == nil && schedulerTimeout != 0 {
		s.Config.SchedulerTimer = schedulerTimeout
	} else if s.Config.SchedulerTimer == 0 {
		s.Config.SchedulerTimer = constants.DefaultSHVSSchedulerTimer
	}

	autoRefreshTimeout, err := c.GetenvInt("SHVS_AUTO_REFRESH_TIMER", "SHVS autoRefresh Timeout Seconds")
	if err == nil && autoRefreshTimeout != 0 {
		s.Config.SHVSRefreshTimer = autoRefreshTimeout
	} else if s.Config.SHVSRefreshTimer == 0 {
		s.Config.SHVSRefreshTimer = constants.DefaultSHVSAutoRefreshTimer
	}

	hostPlatformInfoexpiryTime, err := c.GetenvInt("SHVS_HOST_PLATFORM_EXPIRY_TIME", "SHVS Host Platform Expiry Time in seconds")
	if err == nil && hostPlatformInfoexpiryTime != 0 {
		s.Config.SHVSHostInfoExpiryTime = hostPlatformInfoexpiryTime
	} else if s.Config.SHVSHostInfoExpiryTime == 0 {
		s.Config.SHVSHostInfoExpiryTime = constants.DefaultSHVSHostInfoExpiryTime
	}

	logLevel, err := c.GetenvString(constants.SHVSLogLevel, "SHVS Log Level")
	if err != nil {
		slog.Infof("config/config:SaveConfiguration() %s not defined, using default log level: Info", constants.SHVSLogLevel)
		s.Config.LogLevel = logrus.InfoLevel
	} else {
		llp, err := logrus.ParseLevel(logLevel)
		if err != nil {
			slog.Info("config/config:SaveConfiguration() Invalid log level specified in env, using default log level: Info")
			s.Config.LogLevel = logrus.InfoLevel
		} else {
			s.Config.LogLevel = llp
			slog.Infof("config/config:SaveConfiguration() Log level set %s\n", logLevel)
		}
	}

	logMaxLen, err := c.GetenvInt("SHVS_LOG_MAX_LENGTH", "SGX Host Verification Service Log maximum length")
	if err != nil || logMaxLen < constants.DefaultLogEntryMaxLength {
		s.Config.LogMaxLength = constants.DefaultLogEntryMaxLength
	} else {
		s.Config.LogMaxLength = logMaxLen
	}

	logEnableStdout, err := c.GetenvString("SHVS_ENABLE_CONSOLE_LOG", "SGX Host Verification Service Enable standard output")
	if err != nil || logEnableStdout == "" {
		s.Config.LogEnableStdout = false
	} else {
		s.Config.LogEnableStdout = true
	}

	err = s.Config.Save()
	if err != nil {
		return errors.Wrap(err, "failed to save SHVS config")
	}
	return nil
}

func (s Update_Service_Config) Validate(c setup.Context) error {
	log.Trace("tasks/server:Validate() Entering")
	defer log.Trace("tasks/server:Validate() Leaving")

	return nil
}
