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
	"intel/isecl/cms/v2/config"
	"intel/isecl/lib/common/v2/setup"

	"github.com/stretchr/testify/assert"
)

func TestRootCACertCreation(t *testing.T) {
	log.Trace("tasks/rootca_test:TestRootCACertCreation() Entering")
	defer log.Trace("tasks/rootca_test:TestRootCACertCreation() Leaving")

	assert := assert.New(t)
	CreateSerialNumberFileAndJWTDir()

	temp, _ := ioutil.TempFile("", "config.yml")
	temp.WriteString("keyalgorithm: rsa\nkeyalgorithmlength: 3072\n")
	defer os.Remove(temp.Name())
	c := config.Load(temp.Name())

	_, certData, err := createRootCACert(c)
	assert.NoError(err)
	cert, err := x509.ParseCertificate(certData)
	assert.NoError(err)
	assert.True(cert.IsCA)
}

func TestRootCASetupTaskRun(t *testing.T) {
	log.Trace("tasks/rootca_test:TestRootCASetupTaskRun() Entering")
	defer log.Trace("tasks/rootca_test:TestRootCASetupTaskRun() Leaving")

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
