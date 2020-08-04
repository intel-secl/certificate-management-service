/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package resource

import (
	"net/http"
	"net/http/httptest"
	"io/ioutil"
	"os"
	"intel/isecl/lib/common/v2/setup"
	"intel/isecl/cms/v2/tasks"
	"intel/isecl/cms/v2/config"
	"testing"

	"github.com/stretchr/testify/assert"
)


func TestGetCaCertificates(t *testing.T) {
	log.Trace("resource/ca_certificates_test:TestGetCaCertificates() Entering")
	defer log.Trace("resource/ca_certificates_test:TestGetCaCertificates() Leaving")

	assert := assert.New(t)
	
	os.MkdirAll("/etc/cms", os.ModePerm)
	os.MkdirAll("/etc/cms/root-ca", os.ModePerm)
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

	const bearerToken = "eyJhbGciOiJSUzM4NCIsImtpZCI6IjRiNDA3MmYyNWQ1ZDk1ZWE2NjlmZWRhOWU4NGUzZjJiNWY5ZmM3YzQiLCJ0eXAiOiJKV1QifQ.eyJyb2xlcyI6W3sic2VydmljZSI6IkhWUyIsIm5hbWUiOiJDZXJ0aWZpZXIifSx7InNlcnZpY2UiOiJDTVMiLCJuYW1lIjoiQ2VydEFwcHJvdmVyIiwiY29udGV4dCI6IkNOPUF0dGVzdGF0aW9uIEh1YiBUTFMgQ2VydGlmaWNhdGU7U0FOPTEwLjgwLjI0NS44NyxhcmlqaXQtVk0tMjtjZXJ0VHlwZT1UTFMifSx7InNlcnZpY2UiOiJDTVMiLCJuYW1lIjoiQ2VydEFwcHJvdmVyIiwiY29udGV4dCI6IkNOPUhWUyBGbGF2b3IgU2lnbmluZyBDZXJ0aWZpY2F0ZTtjZXJ0VHlwZT1TaWduaW5nIn0seyJzZXJ2aWNlIjoiQ01TIiwibmFtZSI6IkNlcnRBcHByb3ZlciIsImNvbnRleHQiOiJDTj1IVlMgVExTIENlcnRpZmljYXRlO1NBTj0xMC44MC4yNDUuODcsYXJpaml0LVZNLTI7Y2VydFR5cGU9VExTIn0seyJzZXJ2aWNlIjoiQ01TIiwibmFtZSI6IkNlcnRBcHByb3ZlciIsImNvbnRleHQiOiJDTj1IVlMgU0FNTCBDZXJ0aWZpY2F0ZTtjZXJ0VHlwZT1TaWduaW5nIn0seyJzZXJ2aWNlIjoiQ01TIiwibmFtZSI6IkNlcnRBcHByb3ZlciIsImNvbnRleHQiOiJDTj1LTVMgVExTIENlcnRpZmljYXRlO1NBTj0xMC44MC4yNDUuODcsYXJpaml0LVZNLTI7Y2VydFR5cGU9VExTIn0seyJzZXJ2aWNlIjoiSFZTIiwibmFtZSI6IkF0dGVzdGF0aW9uUmVnaXN0ZXIifSx7InNlcnZpY2UiOiJDTVMiLCJuYW1lIjoiQ2VydEFwcHJvdmVyIiwiY29udGV4dCI6IkNOPVRydXN0IEFnZW50IFRMUyBDZXJ0aWZpY2F0ZTtTQU49KjtjZXJ0VHlwZT1UTFMifSx7InNlcnZpY2UiOiJDTVMiLCJuYW1lIjoiQ2VydEFwcHJvdmVyIiwiY29udGV4dCI6IkNOPVdMUyBUTFMgQ2VydGlmaWNhdGU7U0FOPTEwLjgwLjI0NS44NyxhcmlqaXQtVk0tMjtjZXJ0VHlwZT1UTFMifSx7InNlcnZpY2UiOiJDTVMiLCJuYW1lIjoiQ2VydEFwcHJvdmVyIiwiY29udGV4dCI6IkNOPVdQTSBGbGF2b3IgU2lnbmluZyBDZXJ0aWZpY2F0ZTtjZXJ0VHlwZT1TaWduaW5nIn1dLCJwZXJtaXNzaW9ucyI6W3sic2VydmljZSI6IkhWUyIsInJ1bGVzIjpbImZsYXZvcnM6c2VhcmNoOioiLCJob3N0X2Fpa3M6Y2VydGlmeToqIiwiaG9zdHM6Y3JlYXRlOioiLCJob3N0X3NpZ25pbmdfa2V5X2NlcnRpZmljYXRlczpjcmVhdGU6KiIsImhvc3RzOnNlYXJjaDoqIiwiaG9zdHM6c3RvcmU6KiIsImhvc3RfdGxzX3BvbGljaWVzOmNyZWF0ZToqIiwiaG9zdF91bmlxdWVfZmxhdm9yczpjcmVhdGU6KiIsInRwbV9lbmRvcnNlbWVudHM6Y3JlYXRlOioiLCJ0cG1fZW5kb3JzZW1lbnRzOnNlYXJjaDoqIiwidHBtX3Bhc3N3b3JkczpjcmVhdGU6KiIsInRwbV9wYXNzd29yZHM6cmV0cmlldmU6KiJdfV0sImV4cCI6MjIyNzI1MDIxNCwiaWF0IjoxNTk2NTMwMTg0LCJpc3MiOiJBQVMgSldUIElzc3VlciIsInN1YiI6InN1cGVyYWRtaW4ifQ.qPf5BXv6mORfSi8jkNNOYpJMFMfQYeDgNP2G0RAFmCx0TgM4dJSO3xns_ltee4jImRUFJPHxSMzC6u5MBNL3XcpodLsW72Ubd0fciJAhQWrAduWBzXyaPciAtn8IeZr193gYcSJSe6hhlvOPnwP7yVCHZWznRYIpdPnUip_d8ltPwweZq-iV-U1rDejhVXyKw7o3l7Q6MV8y9RYR2CWUDfGuM4pTa-PFiTk-aU3XV9MvYV99hxBLq-QRA5-lMSYYi0tbg67qheY1pXR0dlLScdPlq3MjoMRuia0FK8Brp7wphzR8nLR5Goj9H6o1AvfE6p_6P5kOA8GzYwcpztSmdo6hpA7BQVV4p7vuq20FoQJqo1Nm21YSgFjjyxmh3vZM1TxNCidgPD-CQz2_IheaIiRt-fHjWI9BfhXvVRz3QUHuMr1BB3QEajj051q3ioe_OFtgsjd8gB2jJ42byUesleLfErWCsGD1tS9YVTAnmjdl9jJ24u8Cs7I7gFSPgFnF"
	req := httptest.NewRequest("GET", "/cms/v1/ca-certificates", nil)
	req.Header.Add("Accept", "application/x-pem-file")
	req.Header.Add("Content-Type", "application/x-pem-file")
	req.Header.Add("Authorization", "Bearer "+bearerToken)
	r.ServeHTTP(recorder, req)
	assert.Equal(http.StatusOK, recorder.Code)
	
}

