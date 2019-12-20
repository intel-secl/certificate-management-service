/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"github.com/pkg/errors"
	"flag"
	"fmt"
	"intel/isecl/lib/common/setup"
	"intel/isecl/cms/config"
	"intel/isecl/cms/constants"
	"io"
	"time"
)

type Server struct {
	Flags         []string
	Config        *config.Configuration
	ConsoleWriter io.Writer
}

func (s Server) Run(c setup.Context) error {
	log.Trace("tasks/server:Run() Entering")
	defer log.Trace("tasks/server:Run() Leaving")

	fmt.Fprintln(s.ConsoleWriter, "Running server setup...")
	defaultPort, err := c.GetenvInt("CMS_PORT", "Certificate Management Service http port")
	if err != nil {
		defaultPort = constants.DefaultPort
	}	
	authServiceUrl, _ := c.GetenvString("AAS_API_URL", "Auth Service http url")

	fs := flag.NewFlagSet("server", flag.ContinueOnError)
	fs.IntVar(&s.Config.Port, "port", defaultPort, "Certificate Management Service http port")
	fs.StringVar(&s.Config.AuthServiceUrl, "aas-url", authServiceUrl, "auth service http url")
	err = fs.Parse(s.Flags)
	if err != nil {
		return errors.Wrap(err, "tasks/server:Run() Could not parse input flags")
	}
	if s.Config.Port > 65535 || s.Config.Port <= 1024 {
		return errors.Wrap(err, "tasks/server:Run() Invalid or reserved port")
	}
	log.Infof("tasks/server:Run() CMS server trying to start on port -%v", s.Config.Port)
	fmt.Fprintf(s.ConsoleWriter, "Using HTTPS port: %d\n", s.Config.Port)
	fmt.Fprintf(s.ConsoleWriter, "Auth Service url :%s", authServiceUrl)

	s.Config.AuthDefender.MaxAttempts = constants.DefaultAuthDefendMaxAttempts
	s.Config.AuthDefender.IntervalMins = constants.DefaultAuthDefendIntervalMins
	s.Config.AuthDefender.LockoutDurationMins = constants.DefaultAuthDefendLockoutMins
	if s.Config.TokenDurationMins == 0 {
		s.Config.TokenDurationMins = constants.DefaultTokenDurationMins
	}

	readTimeout, err := c.GetenvInt("CMS_SERVER_READ_TIMEOUT", "Certificate Management Service Read Timeout")
	if err != nil {
		s.Config.ReadTimeout = constants.DefaultReadTimeout
	} else {
		s.Config.ReadTimeout = time.Duration(readTimeout) * time.Second
	}

	readHeaderTimeout, err := c.GetenvInt("CMS_SERVER_READ_HEADER_TIMEOUT", "Certificate Management Service Read Header Timeout")
	if err != nil {
		s.Config.ReadHeaderTimeout = constants.DefaultReadHeaderTimeout
	} else {
		s.Config.ReadHeaderTimeout = time.Duration(readHeaderTimeout) * time.Second
	}

	writeTimeout, err := c.GetenvInt("CMS_SERVER_WRITE_TIMEOUT", "Certificate Management Service Write Timeout")
	if err != nil {
		s.Config.WriteTimeout = constants.DefaultWriteTimeout
	} else {
		s.Config.WriteTimeout = time.Duration(writeTimeout) * time.Second
	}

	idleTimeout, err := c.GetenvInt("CMS_SERVER_IDLE_TIMEOUT", "Certificate Management Service Idle Timeout")
	if err != nil {
		s.Config.IdleTimeout = constants.DefaultIdleTimeout
	} else {
		s.Config.IdleTimeout = time.Duration(idleTimeout) * time.Second
	}

	maxHeaderBytes, err := c.GetenvInt("CMS_SERVER_MAX_HEADER_BYTES", "Certificate Management Service Max Header Bytes Timeout")
	if err != nil {
		s.Config.MaxHeaderBytes = constants.DefaultMaxHeaderBytes
	} else {
		s.Config.MaxHeaderBytes = maxHeaderBytes
	}

	logEntryMaxLength, err := c.GetenvInt(constants.LogEntryMaxlengthEnv, "Maximum length of each entry in a log")
	if err == nil && logEntryMaxLength >= 100 {
		s.Config.LogEntryMaxLength = logEntryMaxLength
	} else {
		fmt.Println("Invalid Log Entry Max Length defined (should be > 100), using default value:", constants.DefaultLogEntryMaxlength)
		s.Config.LogEntryMaxLength = constants.DefaultLogEntryMaxlength
	}

	s.Config.Save()
	return nil
}

func (s Server) Validate(c setup.Context) error {
	log.Trace("tasks/server:Validate() Entering")
	defer log.Trace("tasks/server:Validate() Leaving")

	return nil
}
