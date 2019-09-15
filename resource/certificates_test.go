/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package resource

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"crypto/rsa"
	"crypto/x509/pkix"
	"encoding/pem"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"intel/isecl/lib/common/setup"
	"intel/isecl/cms/tasks"
	"intel/isecl/cms/config"
	"testing"

	"github.com/stretchr/testify/assert"
)


func TestGetCertificatesForCsr(t *testing.T) {
	assert := assert.New(t)
	
	os.MkdirAll("/etc/cms", os.ModePerm)
        var file, _ = os.Create("/etc/cms/serial-number")
        defer file.Close()

        temp, _ := ioutil.TempFile("", "config.yml")
        temp.WriteString("keyalgorithm: rsa\nkeyalgorithmlength: 3072\n")
        defer os.Remove(temp.Name())
        c := config.Load(temp.Name())

        ca := tasks.Root_Ca{
                Flags:         nil,
                ConsoleWriter: os.Stdout,
                Config: c,
        }
        
	ctx := setup.Context{}
        err := ca.Run(ctx)
        assert.NoError(err)

	r := setupRouter()
	recorder := httptest.NewRecorder()

	keyBytes, _ := rsa.GenerateKey(rand.Reader, 3072)
	
	var extensions []pkix.Extension
    	var oidExtensionBasicConstraints = []int{2, 5, 29, 19} //export from x509 package
	oidExtensionKeyUsage := []int{2, 5, 29, 15}
    	bcExt := pkix.Extension{Id: oidExtensionBasicConstraints, Critical: true,  Value: []byte{70, 128, 160, 70}}
	bcExt2 := pkix.Extension{Id: oidExtensionKeyUsage, Critical: true,  Value: []byte{70, 128, 160, 70}}
    	extensions = append(extensions, bcExt)
	extensions = append(extensions, bcExt2)
	
	csrTemplate := x509.CertificateRequest{
		SignatureAlgorithm: x509.SHA384WithRSA,

		DNSNames: []string{"disney"},

		Subject: pkix.Name{
			CommonName:         "AAS TLS Certificate",
			Country:            []string{"US"},
			Province:           []string{"CA"},
			Locality:           []string{"FM"},
			Organization:       []string{"INTEL"},
			OrganizationalUnit: []string{"IT"},
		},
		ExtraExtensions:    extensions,
	}

	csrBytes, _ := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, keyBytes)
	buffer := new(bytes.Buffer)
	pem.Encode(buffer, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})
	csrCert := buffer.String()
	const bearerToken = "eyJhbGciOiJFUzM4NCIsImtpZCI6IjJlYzcxN2E3MDFhZjM4MGU5MGYxYmI4MjIxY2Q5MjQyY2QzNmZkNWMiLCJ0eXAiOiJKV1QifQ.eyJyb2xlcyI6W3sic2VydmljZSI6IkFBUyIsIm5hbWUiOiJSb2xlTWFuYWdlciJ9LHsic2VydmljZSI6IkFBUyIsIm5hbWUiOiJVc2VyTWFuYWdlciJ9LHsic2VydmljZSI6IkFBUyIsIm5hbWUiOiJVc2VyUm9sZU1hbmFnZXIifSx7InNlcnZpY2UiOiJDTVMiLCJuYW1lIjoiQ2VydEFwcHJvdmVyIiwiY29udGV4dCI6IkNOPUFBUyBKV1QgU2lnbmluZyBDZXJ0aWZpY2F0ZSJ9LHsic2VydmljZSI6IkNNUyIsIm5hbWUiOiJDZXJ0QXBwcm92ZXIiLCJjb250ZXh0IjoiQ049QUFTIFRMUyBDZXJ0aWZpY2F0ZSJ9XSwiZXhwIjoxNzIwNDQ5OTU2LCJpYXQiOjE1NjI3Njk5NTYsImlzcyI6IkFBUyBKV1QgSXNzdWVyIiwic3ViIjoiYWRtaW4ifQ.509O6CiWaL_nJW7xSY-fgo8uepZXPLNj4AbeF0sj10kn8qVV6z2TTtpHrA-b-0RvH84Us4t9yr0XAfX9vfBY366WQXM370h812vpP9D08T6wQ0OfRhCfvghXn0hp86w2"
	req := httptest.NewRequest("POST", "/cms/v1/certificates", bytes.NewBuffer([]byte(csrCert)))
	req.Header.Add("Accept", "application/x-pem-file")
	req.Header.Add("Content-Type", "application/x-pem-file")
	req.Header.Add("Authorization", "Bearer "+bearerToken)
	r.ServeHTTP(recorder, req)
	assert.Equal(http.StatusOK, recorder.Code)
	
}

