/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"crypto/x509"
	"intel/isecl/cms/config"
	"intel/isecl/lib/common/setup"
	"os"
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTlsCertCreation(t *testing.T) {
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

	ts := TLS{
		Flags:         []string{""},
		ConsoleWriter: os.Stdout,
		Config: c,
	}
	keyData, certData, err := createTLSCert(ts, "intel.com")
	assert.NoError(err)
	_, err = x509.ParsePKCS8PrivateKey(keyData)
	assert.NoError(err)
	cert, err := x509.ParseCertificate(certData)
	assert.NoError(err)
	assert.Contains(cert.DNSNames, "intel.com")
	assert.NoError(cert.VerifyHostname("intel.com"))
}

func TestTlsSetupTaskRun(t *testing.T){
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

        ts := TLS{
                Flags:         []string{""},
                ConsoleWriter: os.Stdout,
                Config: c,
        }
	err = ts.Run(ctx)
	assert.NoError(err)
}

func TestOutboundHost(t *testing.T) {
	host, err := outboundHost()
	assert.NoError(t, err)
	assert.NotNil(t, host)
}
