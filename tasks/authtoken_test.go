/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

 package tasks

import (
        "testing"
        "os"
        "intel/isecl/cms/v2/config"
        "intel/isecl/lib/common/v2/setup"

        "github.com/stretchr/testify/assert"
)

func TestCreateCmsAuthToken(t *testing.T){
        log.Trace("tasks/authtoken_test:TestCreateCmsAuthToken() Entering")
	defer log.Trace("tasks/authtoken_test:TestCreateCmsAuthToken() Leaving")

	assert := assert.New(t)
        os.Setenv("CMS_KEY_ALGORITHM", "RSA")
        os.Setenv("CMS_KEY_LENGTH", "3072")
	CreateSerialNumberFileAndJWTDir()
        c := config.Configuration{}

        at := Cms_Auth_Token{
                Flags:         nil,
                ConsoleWriter: os.Stdout,
                Config: &c,
        }

        ctx := setup.Context{}
        err := createCmsAuthToken(at, ctx)
        assert.NoError(err)
        //defer os.RemoveAll("/etc/cms")
}


func TestAuthTokenRun(t *testing.T) {
        log.Trace("tasks/authtoken_test:TestAuthTokenRun() Entering")
	defer log.Trace("tasks/authtoken_test:TestAuthTokenRun() Leaving")

        assert := assert.New(t)
        os.Setenv("CMS_KEY_ALGORITHM", "RSA")
        os.Setenv("CMS_KEY_LENGTH", "3072")
	CreateSerialNumberFileAndJWTDir()
        c := config.Configuration{}

        ca := Cms_Auth_Token{
                Flags:         nil,
                ConsoleWriter: os.Stdout,
                Config: &c,
        }

        ctx := setup.Context{}
        err := ca.Run(ctx)
        assert.NoError(err)
}

