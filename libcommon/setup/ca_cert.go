/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package setup

import (
        "crypto"
        "fmt"
        "flag"
        "io"
        "os"
        "errors"
        "io/ioutil"
        "net/http"
        "net/url"
        "crypto/tls"
        "intel/isecl/cms/libcommon/crypt"
        "intel/isecl/lib/common/setup"
)

type Download_Ca_Cert struct {
        Flags           []string
        CaCertDirPath   string        
	ConsoleWriter   io.Writer
}

func DownloadRootCaCertificate(cmsBaseUrl string, dirPath string, trustDigest string) (err error) {        
        url, err := url.Parse(cmsBaseUrl)
        if err != nil {
                fmt.Println("Configured CMS URL is malformed: ", err)
                return fmt.Errorf("CA certificate setup: %v", err)
        }
        certificates, _ := url.Parse("ca-certificates")
        endpoint := url.ResolveReference(certificates)
        req, err := http.NewRequest("GET", endpoint.String(), nil)
        if err != nil {
                fmt.Println("Failed to instantiate http request to CMS")
                return fmt.Errorf("CA certificate setup: %v", err)
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
                return fmt.Errorf("CA certificate setup: %v", err)
        }
        defer resp.Body.Close()
        if resp.StatusCode != http.StatusOK {
                text, _ := ioutil.ReadAll(resp.Body)
                errStr := fmt.Sprintf("CMS request failed to download CA certificate (HTTP Status Code: %d)\nMessage: %s", resp.StatusCode, string(text))
                fmt.Println(errStr)
                return fmt.Errorf("CA certificate setup: %v", err)
        }
        tlsResp, err := ioutil.ReadAll(resp.Body)
        if err != nil {
                fmt.Println("Failed to read CMS response body")
                return fmt.Errorf("CA certificate setup: %v", err)
        }        
        if tlsResp != nil {
                caDigest, err := crypt.GetCertHashFromPemInHex(tlsResp, crypto.SHA384)
                if err != nil {
                        fmt.Println("Could not find certificate digest")
                        return fmt.Errorf("CA certificate setup: %v", err)
                } else if trustDigest != caDigest {                        
                        fmt.Println("Digest does not match, untrusted CA " )
                        return fmt.Errorf("CA certificate setup: %v", err)
                } 
                err = crypt.SavePemCertWithShortSha1FileName(tlsResp, dirPath)
                if err != nil {
                        fmt.Println("Could not save CA certificate")
                        return fmt.Errorf("CA certificate setup: %v", err)
                }
        } else {
                fmt.Println("Invalid response from Download CA Certificate")
                return fmt.Errorf("Invalid response from Download CA Certificate")
        }        
        return nil        
}

func (cc Download_Ca_Cert) Run(c setup.Context) error {
        fmt.Fprintln(cc.ConsoleWriter, "Running CA certificate download setup...")
        fs := flag.NewFlagSet("ca", flag.ContinueOnError)
        force := fs.Bool("force", false, "force recreation, will overwrite any existing certificate")
        
        err := fs.Parse(cc.Flags)
        if err != nil {
                fmt.Println("CA certificate setup: Unable to parse flags") 
                return fmt.Errorf("CA certificate setup: Unable to parse flags") 
        }
        cmsBaseUrl, err := c.GetenvString("CMS_BASE_URL", "CMS base URL in https://{{cms}}:{{cms_port}}/cms/v1/")
	 if err != nil || cmsBaseUrl == "" {
                fmt.Println("CMS_BASE_URL not found in environment for Download CA Certificate") 
                return fmt.Errorf("CMS_BASE_URL not found in environment for Download CA Certificate") 
         }
         caCertTrustedDigest, err := c.GetenvString("CA_CERT_DIGEST", "Trusted CMS CA certificate SHA384 digest")
	 if err != nil || caCertTrustedDigest == "" {
                fmt.Println("CA_CERT_DIGEST not found in environment for Download CA Certificate") 
                return fmt.Errorf("CA_CERT_DIGEST not found in environment for Download CA Certificate") 
         }

        if *force || cc.Validate(c) != nil {
                err = DownloadRootCaCertificate(cmsBaseUrl, cc.CaCertDirPath, caCertTrustedDigest)
                if err != nil {
                        fmt.Println("Failed to Download CA Certificate") 
                        return err
                 }
        } else {
                fmt.Println("CA certificate already downloaded, skipping")
        }           
         return nil  
}

func (cc Download_Ca_Cert) Validate(c setup.Context) error {	 
        fmt.Fprintln(cc.ConsoleWriter, "Validating CA certificate download setup...")
        ok, err := IsDirEmpty(cc.CaCertDirPath)
         if err != nil {
                return errors.New("Error opening CA certificate directory")
         }
         if ok == true {
                return errors.New("CA certificate is not downloaded")
         }
	 return nil
 }

 func IsDirEmpty(name string) (bool, error) {
        f, err := os.Open(name)
        if err != nil {
            return false, err
        }
        defer f.Close()
    
        _, err = f.Readdirnames(1)
        if err == io.EOF {
            return true, nil
        }
        return false, err
}