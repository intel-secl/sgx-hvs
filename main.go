/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package main

import (
	"intel/isecl/shvs/v3/constants"
	_ "intel/isecl/shvs/v3/swagger/docs"
	"os"
	"os/user"
	"strconv"
)

func openLogFiles() (logFile *os.File, httpLogFile *os.File, secLogFile *os.File, err error) {
	logFile, err = os.OpenFile(constants.LogFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return nil, nil, nil, err
	}
	err = os.Chmod(constants.LogFile, 0600)
	if err != nil {
		return nil, nil, nil, err
	}

	httpLogFile, err = os.OpenFile(constants.HTTPLogFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return nil, nil, nil, err
	}
	err = os.Chmod(constants.HTTPLogFile, 0600)
	if err != nil {
		return nil, nil, nil, err
	}

	secLogFile, err = os.OpenFile(constants.SecurityLogFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return nil, nil, nil, err
	}
	err = os.Chmod(constants.SecurityLogFile, 0600)
	if err != nil {
		return nil, nil, nil, err
	}

	shvsUser, err := user.Lookup(constants.SHVSUserName)
	if err != nil {
		log.Errorf("Could not find user '%s'", constants.SHVSUserName)
		return nil, nil, nil, err
	}

	uid, err := strconv.Atoi(shvsUser.Uid)
	if err != nil {
		log.Errorf("Could not parse shvs user uid '%s'", shvsUser.Uid)
		return nil, nil, nil, err
	}

	gid, err := strconv.Atoi(shvsUser.Gid)
	if err != nil {
		log.Errorf("Could not parse shvs user gid '%s'", shvsUser.Gid)
		return nil, nil, nil, err
	}

	err = os.Chown(constants.HTTPLogFile, uid, gid)
	if err != nil {
		log.Errorf("Could not change file ownership for file: '%s'", constants.HTTPLogFile)
		return nil, nil, nil, err
	}

	err = os.Chown(constants.SecurityLogFile, uid, gid)
	if err != nil {
		log.Errorf("Could not change file ownership for file: '%s'", constants.SecurityLogFile)
	}

	err = os.Chown(constants.LogFile, uid, gid)
	if err != nil {
		log.Errorf("Could not change file ownership for file: '%s'", constants.LogFile)
		return nil, nil, nil, err
	}

	return
}

func main() {

	l, h, s, err := openLogFiles()
	var app *App
	if err != nil {
		app = &App{
			LogWriter: os.Stdout,
		}
	} else {
		defer func() {
			err = l.Close()
			if err != nil {
				log.Error("failed to complete write on shvs.log ", err)
				os.Exit(1)
			}
			err = h.Close()
			if err != nil {
				log.Error("failed to complete write on shvs-http.log ", err)
				os.Exit(1)
			}
			err = s.Close()
			if err != nil {
				log.Error("failed to complete write on shvs-security.log ", err)
				os.Exit(1)
			}
		}()
		app = &App{
			LogWriter:     l,
			HTTPLogWriter: h,
			SecLogWriter:  s,
		}
	}
	err = app.Run(os.Args)
	if err != nil {
		log.Error("Application returned with error: ", err)
		os.Exit(1)
	}
}
