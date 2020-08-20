/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package tasks

import (
	"intel/isecl/lib/common/v3/setup"
	"intel/isecl/cms/v3/config"
	"os"

	"testing"

	"github.com/stretchr/testify/assert"
)

func TestServerSetupEnv(t *testing.T) {
	log.Trace("tasks/server_test:TestServerSetupEnv() Entering")
	defer log.Trace("tasks/server_test:TestServerSetupEnv() Leaving")

	os.Setenv("CMS_PORT", "1337")
	os.Setenv("CMS_KEY_ALGORITHM", "RSA")
	os.Setenv("CMS_KEY_LENGTH", "3072")
	os.Setenv("AAS_API_URL","https://192.178.182.1:1337/aas")
	c := config.Configuration{}
	s := Server{
		Flags:         nil,
		Config:        &c,
		ConsoleWriter: os.Stdout,
	}
	ctx := setup.Context{}
	s.Run(ctx)
	assert.Equal(t, 1337, c.Port)
}

