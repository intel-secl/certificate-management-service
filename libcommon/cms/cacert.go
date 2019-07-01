/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package cms

import (
        "fmt"
        "io/ioutil"
        "net/http"
        "net/url"
        "crypto/tls"
        "encoding/pem"	
        "intel/isecl/cms/libcommon/crypt"
        log "github.com/sirupsen/logrus"
)

func DownloadRootCaCertificate(cmsBaseUrl string, filePath string) {        
        url, err := url.Parse(cmsBaseUrl)
        if err != nil {
                log.Errorf("Invalid CSR provided: %v", err)
                fmt.Println("Configured CMS URL is malformed: ", err)
                return
        }
        certificates, _ := url.Parse("ca-certificates")
        endpoint := url.ResolveReference(certificates)
        req, err := http.NewRequest("GET", endpoint.String(), nil)
        if err != nil {
                fmt.Println("Failed to instantiate http request to CMS")
                return
        }
        req.Header.Set("Accept", "application/x-pem-file")        
        client := &http.Client{
                Transport: &http.Transport{
                        TLSClientConfig: &tls.Config{
                                InsecureSkipVerify: true,
                        },
                },
        }
        resp, err := client.Do(req)
        if err != nil {
                fmt.Println("Failed to perform HTTP request to CMS")
                return
        }
        defer resp.Body.Close()
        if resp.StatusCode != http.StatusOK {
                text, _ := ioutil.ReadAll(resp.Body)
                errStr := fmt.Sprintf("CMS request failed to tls certificate signed (HTTP Status Code: %d)\nMessage: %s", resp.StatusCode, string(text))
                fmt.Println(errStr)
                return
        }
        tlsResp, err := ioutil.ReadAll(resp.Body)
        if err != nil {
                fmt.Println("Failed to read HVS response body")
                return
        }
        if tlsResp != nil {
                block, _ := pem.Decode(tlsResp)
                if block == nil {
                        return
                }
                crypt.SavePemCert(block.Bytes, filePath)
        }
}