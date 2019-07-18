/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

 package tasks

import (
	"crypto/x509"
	"testing"
	"os"
	"io/ioutil"
	"intel/isecl/cms/config"
	"intel/isecl/lib/common/setup"

	"github.com/stretchr/testify/assert"
)

func TestRootCACertCreation(t *testing.T) {
	assert := assert.New(t)
	CreateSerialNumberFileAndJWTDir()

	temp, _ := ioutil.TempFile("", "config.yml")
	temp.WriteString("keyalgorithm: rsa\nkeyalgorithmlength: 3072\n")
	defer os.Remove(temp.Name())
	c := config.Load(temp.Name())

	ca := Root_Ca{
		Flags:         nil,
		ConsoleWriter: os.Stdout,
		Config: c,	
	}

	_, certData, err := createRootCACert(ca)
	assert.NoError(err)
	cert, err := x509.ParseCertificate(certData)
	assert.NoError(err)
	assert.True(cert.IsCA)
}

func TestRootCASetupTaskRun(t *testing.T) {
	assert := assert.New(t)
	CreateSerialNumberFileAndJWTDir()

        temp, _ := ioutil.TempFile("", "config.yml")
        temp.WriteString("keyalgorithm: rsa\nkeyalgorithmlength: 3072\n")
        defer os.Remove(temp.Name())
        c := config.Load(temp.Name())

        ca := Root_Ca{
                Flags:         nil,
                ConsoleWriter: os.Stdout,
                Config: c,
        }
	
	ctx := setup.Context{}
	err := ca.Run(ctx)
	assert.NoError(err)
}
