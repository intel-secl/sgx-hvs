/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"flag"
	"fmt"
	"intel/isecl/sgx-host-verification-service/repository"
	"intel/isecl/lib/common/setup"
	"io"

	commLog "intel/isecl/lib/common/log"
	"github.com/pkg/errors"
)

type Admin struct {
	Flags           []string
	DatabaseFactory func() (repository.SHVSDatabase, error)
	ConsoleWriter   io.Writer
}

var log = commLog.GetDefaultLogger()
var slog = commLog.GetSecurityLogger()

func (a Admin) Run(c setup.Context) error {
	fmt.Fprintln(a.ConsoleWriter, "Running admin setup...")
	fs := flag.NewFlagSet("admin", flag.ContinueOnError)
	err := fs.Parse(a.Flags)
	if err != nil {
		return errors.Wrap(err, "setup admin: failed to parse cmd flags")
	}
	db, err := a.DatabaseFactory()
	if err != nil {
		log.WithError(err).Error("failed to open database")
		return errors.Wrap(err, "setup admin: failed to open database")
	}
	defer db.Close()
	return nil
}

func (a Admin) Validate(c setup.Context) error {
	return nil
}
