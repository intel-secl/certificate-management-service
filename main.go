/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package main

import (
	"intel/isecl/cms/constants"
	"os"
	"path"
)

func openLogFiles() (httpLogFile *os.File) {
	log.Trace("main:openLogFiles() Entering")
	defer log.Trace("main:openLogFiles() Leaving")

	httpLogFilePath := path.Join(constants.LogDir, constants.HTTPLogFile)
	httpLogFile, err := os.OpenFile(httpLogFilePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0664)
	if err != nil {
		log.Errorf("Could not open HTTP log file")
	}
	os.Chmod(httpLogFilePath, 0664)
	return
}

func main() {
	log.Trace("main:main() Entering")
	defer log.Trace("main:main() Leaving")

	h := openLogFiles()
	defer h.Close()
	app := &App{
		HTTPLogWriter: h,
	}
	err := app.Run(os.Args)
	if err != nil {
		log.WithError(err).Error("main:main() CMS application error")		
		log.Tracef("%+v",err)
		os.Exit(1)
	}
}
