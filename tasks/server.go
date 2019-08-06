/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"errors"
	"flag"
	"fmt"
	"intel/isecl/lib/common/setup"
	"intel/isecl/cms/config"
	"intel/isecl/cms/constants"
	"io"
)

type Server struct {
	Flags         []string
	Config        *config.Configuration
	ConsoleWriter io.Writer
}

func (s Server) Run(c setup.Context) error {
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
		return err
	}
	if s.Config.Port > 65535 || s.Config.Port <= 1024 {
		return errors.New("Invalid or reserved port")
	}
	fmt.Fprintf(s.ConsoleWriter, "Using HTTPS port: %d\n", s.Config.Port)
	fmt.Fprintf(s.ConsoleWriter, "service url :%s", authServiceUrl)

	s.Config.KeyAlgorithm, err = c.GetenvString("CMS_KEY_ALGORITHM", "Certificate Management Service Key Algorithm")
	if err != nil {
		s.Config.KeyAlgorithm = constants.DefaultKeyAlgorithm
	} 

	s.Config.KeyAlgorithmLength, err = c.GetenvInt("CMS_KEY_ALGORITHM_LENGTH", "Certificate Management Service Key Algorithm Length")
	if err != nil {
		s.Config.KeyAlgorithmLength = constants.DefaultKeyAlgorithmLength
	}
	s.Config.AuthDefender.MaxAttempts = constants.DefaultAuthDefendMaxAttempts
	s.Config.AuthDefender.IntervalMins = constants.DefaultAuthDefendIntervalMins
	s.Config.AuthDefender.LockoutDurationMins = constants.DefaultAuthDefendLockoutMins
	if s.Config.TokenDurationMins == 0 {
		s.Config.TokenDurationMins = constants.DefaultTokenDurationMins
	}
	s.Config.Save()
	return nil
}

func (s Server) Validate(c setup.Context) error {
	return nil
}
