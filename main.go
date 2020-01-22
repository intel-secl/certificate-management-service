/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package main

import (
	"intel/isecl/cms/constants"

	"os"
	"os/user"
	"strconv"
)

func openLogFiles() (logFile *os.File, httpLogFile *os.File, secLogFile *os.File) {

        logFile, _ = os.OpenFile(constants.LogFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0664)
        os.Chmod(constants.LogFile, 0664)

        httpLogFile, _ = os.OpenFile(constants.HTTPLogFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0664)
        os.Chmod(constants.HTTPLogFile, 0664)

        secLogFile, _ = os.OpenFile(constants.SecurityLogFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0664)
        os.Chmod(constants.SecurityLogFile, 0664)

        cmsUser, err := user.Lookup(constants.CMSUserName)
        if err != nil {
                log.Errorf("Could not find user '%s'", constants.CMSUserName)
        }

        uid, err := strconv.Atoi(cmsUser.Uid)
        if err != nil {
                log.Errorf("Could not parse cms user uid '%s'", cmsUser.Uid)
        }

        gid, err := strconv.Atoi(cmsUser.Gid)
        if err != nil {
                log.Errorf("Could not parse cms user gid '%s'", cmsUser.Gid)
        }

        err = os.Chown(constants.HTTPLogFile, uid, gid)
        if err != nil {
                log.Errorf("Could not change file ownership for file: '%s'", constants.HTTPLogFile)
        }
        err = os.Chown(constants.SecurityLogFile, uid, gid)
        if err != nil {
                log.Errorf("Could not change file ownership for file: '%s'", constants.SecurityLogFile)
        }
        err = os.Chown(constants.LogFile, uid, gid)
        if err != nil {
                log.Errorf("Could not change file ownership for file: '%s'", constants.LogFile)
        }

        return
}

func main() {
	log.Trace("main:main() Entering")
	defer log.Trace("main:main() Leaving")
        l, h, s := openLogFiles()
        defer l.Close()
        defer h.Close()
        defer s.Close()
        app := &App{
                LogWriter:     l,
                HTTPLogWriter: h,
                SecLogWriter:  s,
        }

	err := app.Run(os.Args)
	if err != nil {
		log.WithError(err).Error("main:main() CMS application error")		
		log.Tracef("%+v",err)
		os.Exit(1)
	}
}
