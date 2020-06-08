/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package main

import (
	"intel/isecl/sgx-host-verification-service/constants"
	"os"
        "os/user"
        "strconv"
)

func openLogFiles() (logFile *os.File, httpLogFile *os.File, secLogFile *os.File, err error) {
        logFile, err = os.OpenFile(constants.LogFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0664)
        if err != nil {
                return nil, nil, nil, err
        }
        os.Chmod(constants.LogFile, 0664)

        httpLogFile, err = os.OpenFile(constants.HTTPLogFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
        if err != nil {
                return nil, nil, nil, err
        }
        os.Chmod(constants.HTTPLogFile, 0664)

        secLogFile, err = os.OpenFile(constants.SecurityLogFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
        if err != nil {
                return nil, nil, nil, err
        }
        os.Chmod(constants.SecurityLogFile, 0664)

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
                defer l.Close()
                defer h.Close()
                defer s.Close()
                app = &App{
                        LogWriter: l,
                        HTTPLogWriter: h,
                        SecLogWriter: s,
                }
        }
        err = app.Run(os.Args)
        if err != nil {
                os.Exit(1)
        }
}
