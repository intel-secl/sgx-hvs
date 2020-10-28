/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"flag"
	"fmt"
	"github.com/pkg/errors"
	commLog "intel/isecl/lib/common/v3/log"
	"intel/isecl/lib/common/v3/setup"
	"intel/isecl/shvs/v3/config"
	"intel/isecl/shvs/v3/constants"
	"io"
	"time"
)

type Server struct {
	Flags         []string
	Config        *config.Configuration
	ConsoleWriter io.Writer
}

var log = commLog.GetDefaultLogger()
var seclog = commLog.GetSecurityLogger()

func (s Server) Run(c setup.Context) error {
	log.Trace("tasks/server:Run() Entering")
	defer log.Trace("tasks/server:Run() Leaving")

	fmt.Fprintln(s.ConsoleWriter, "Running server setup...")
	defaultPort, err := c.GetenvInt("SHVS_PORT", "SGX Host Verification secure port")
	if err != nil {
		defaultPort = constants.DefaultHttpsPort
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

	readTimeout, err := c.GetenvInt("SHVS_SERVER_READ_TIMEOUT", "SGX Host Verification Service Read Timeout")
	if err != nil {
		s.Config.ReadTimeout = constants.DefaultReadTimeout
	} else {
		s.Config.ReadTimeout = time.Duration(readTimeout) * time.Second
	}

	readHeaderTimeout, err := c.GetenvInt("SHVS_SERVER_READ_HEADER_TIMEOUT", "SGX Host Verification Service Read Header Timeout")
	if err != nil {
		s.Config.ReadHeaderTimeout = constants.DefaultReadHeaderTimeout
	} else {
		s.Config.ReadHeaderTimeout = time.Duration(readHeaderTimeout) * time.Second
	}

	writeTimeout, err := c.GetenvInt("SHVS_SERVER_WRITE_TIMEOUT", "SGX Host Verification Service Write Timeout")
	if err != nil {
		s.Config.WriteTimeout = constants.DefaultWriteTimeout
	} else {
		s.Config.WriteTimeout = time.Duration(writeTimeout) * time.Second
	}

	idleTimeout, err := c.GetenvInt("SHVS_SERVER_IDLE_TIMEOUT", "SGX Host Verification Service Service Idle Timeout")
	if err != nil {
		s.Config.IdleTimeout = constants.DefaultIdleTimeout
	} else {
		s.Config.IdleTimeout = time.Duration(idleTimeout) * time.Second
	}

	maxHeaderBytes, err := c.GetenvInt("SHVS_SERVER_MAX_HEADER_BYTES", "SGX Host Verification Service Max Header Bytes Timeout")
	if err != nil {
		s.Config.MaxHeaderBytes = constants.DefaultMaxHeaderBytes
	} else {
		s.Config.MaxHeaderBytes = maxHeaderBytes
	}

	logMaxLen, err := c.GetenvInt("SHVS_LOG_MAX_LENGTH", "SGX Host Verification Service Log maximum length")
	if err != nil || logMaxLen < constants.DefaultLogEntryMaxLength {
		s.Config.LogMaxLength = constants.DefaultLogEntryMaxLength
	} else {
		s.Config.LogMaxLength = logMaxLen
	}

	s.Config.LogEnableStdout = false
	logEnableStdout, err := c.GetenvString("SHVS_ENABLE_CONSOLE_LOG", "SGX Host Verification Service Enable standard output")
	if err != nil || len(logEnableStdout) == 0 {
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

func (s Server) Validate(c setup.Context) error {
	log.Trace("tasks/server:Validate() Entering")
	defer log.Trace("tasks/server:Validate() Leaving")

	return nil
}
