/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package config

import (
	"io/ioutil"
	"os"
	"strconv"
	
	"github.com/pkg/errors"
)

// Need to move these to lib common
// CheckPidFile checks if /var/run/cms/cms.pid exists
func CheckPidFile(path string) (pid int, err error) {
	log.Trace("config/pid:CheckPidFile() Entering")
	defer log.Trace("config/pid:CheckPidFile() Leaving")

	pidData, err := ioutil.ReadFile(path)
	if err != nil {
		return 0, errors.Wrap(err, "config/pid:CheckPidFile() Failed to read pidfile")
	}
	pid, err = strconv.Atoi(string(pidData))
	if err != nil {
		log.WithError(err).WithField("pid", pidData).Debug("config/pid:CheckPidFile() Failed to convert pidData string to int")
		return 0, errors.Wrap(err, "config/pid:CheckPidFile() Failed to convert pidData string to int")
	}
	return pid, nil
}

// WritePidFile writes the specified pid to /var/run/cms/cms.pid,
// creating it if it doesnt exist
func WritePidFile(path string, pid int) error {
	log.Trace("config/pid:WritePidFile() Entering")
	defer log.Trace("config/pid:WritePidFile() Leaving")

	log.WithField("pid", pid).Debug("config/pid:WritePidFile() Writing pid file")
	pidFile, err := os.Create(path)
	if err != nil {
		return errors.Wrap(err, "config/pid:WritePidFile() Failed to write pid file")
	}
	defer pidFile.Close()
	pidFile.WriteString(strconv.Itoa(pid))
	return nil
}
