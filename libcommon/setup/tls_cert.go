/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
 package setup

 import (
		 "fmt"
		 "flag"
		 "io"
		 "os"
		 "bytes"
		 "strings"
		 "errors"
		 "io/ioutil"
		 "net/http"
		 "net/url"
		 "crypto/tls"
		 "encoding/pem"
		 "intel/isecl/lib/common/validation"
		 "intel/isecl/cms/libcommon/crypt"
		 "intel/isecl/lib/common/setup"
 )
 
 type Download_Tls_Cert struct {
		 Flags              []string
		 TLSKeyFile         string     
		 TLSCertFile        string 
		 KeyAlgorithm       string
		 KeyAlgorithmLength int
		 CommonName         string
		 SanList            string
		 BearerToken        string
	     ConsoleWriter      io.Writer
 }

 func createTLSCert(tc Download_Tls_Cert, cmsBaseUrl string, commonName string, hosts string, bearerToken string) (key []byte, cert []byte, err error) {	
	csrData, key, err := crypt.CreateKeyPairAndCertificateRequest(commonName, hosts, tc.KeyAlgorithm, tc.KeyAlgorithmLength)
	if err != nil {
	   return nil, nil, fmt.Errorf("TLS certificate setup: %v", err)
	}	

   url, err := url.Parse(cmsBaseUrl)
   if err != nil {
		   fmt.Println("Configured CMS URL is malformed: ", err)
		   return nil, nil, fmt.Errorf("TLS certificate setup: %v", err)
   }
   certificates, _ := url.Parse("certificates")
   endpoint := url.ResolveReference(certificates)
   csrPemBytes := pem.EncodeToMemory(&pem.Block{Type: "BEGIN CERTIFICATE REQUEST", Bytes: csrData})
   _ = ioutil.WriteFile("/opt/cms/csr.pem", csrPemBytes, 0660)
   req, err := http.NewRequest("POST", endpoint.String(),  bytes.NewBuffer(csrPemBytes))
   if err != nil {
		   fmt.Println("Failed to instantiate http request to CMS")
		   return nil, nil, fmt.Errorf("TLS certificate setup: %v", err)
   }
   req.Header.Set("Accept", "application/x-pem-file")        
   req.Header.Set("Content-Type", "application/x-pem-file")      
   req.Header.Set("Authorization", "Bearer " + bearerToken)  
   // TODO: Add root CA
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
		   return nil, nil, fmt.Errorf("TLS certificate setup: %v", err)
   }
   defer resp.Body.Close()
   if resp.StatusCode != http.StatusOK {
		   text, _ := ioutil.ReadAll(resp.Body)
		   errStr := fmt.Sprintf("CMS request failed to download TLS certificate (HTTP Status Code: %d)\nMessage: %s", resp.StatusCode, string(text))
		   fmt.Println(errStr)
		   return nil, nil, fmt.Errorf("TLS certificate setup: %v", err)
   }
   cert, err = ioutil.ReadAll(resp.Body)
   if err != nil {
		   fmt.Println("Failed to read CMS response body")
		   return nil, nil, fmt.Errorf("TLS certificate setup: %v", err)
   }   
	return
}
 
 func (tc Download_Tls_Cert) Run(c setup.Context) error {
		 fmt.Fprintln(tc.ConsoleWriter, "Running TLS certificate download setup...")
		 fs := flag.NewFlagSet("tls", flag.ContinueOnError)
		 force := fs.Bool("force", false, "force recreation, will overwrite any existing certificate")
		 
		 err := fs.Parse(tc.Flags)
		 if err != nil {				 
				 return errors.New("TLS certificate setup: Unable to parse flags") 
		 }
		 cmsBaseUrl, err := c.GetenvString("CMS_BASE_URL", "CMS base URL in https://{{cms}}:{{cms_port}}/cms/v1/")
	     if err != nil || cmsBaseUrl == "" {			     
				 return errors.New("TLS certificate setup: CMS_BASE_URL not found in environment for Download TLS Certificate") 
		 }

		defaultHostname, err := c.GetenvString("TLS_HOST_NAMES", "Comma separated list of hostnames to add to TLS certificate")
		if err != nil {
			defaultHostname = tc.SanList
		}
		host := fs.String("host_names", defaultHostname, "Comma separated list of hostnames to add to TLS certificate")
 
		bearerToken := tc.BearerToken
		tokenFromEnv, err := c.GetenvString("CMS_BEARER_TOKEN", "CMS bearer token")
	    if err == nil {
			bearerToken = tokenFromEnv
		}
		if bearerToken == "" {			
			return errors.New("TLS certificate setup: CMS_BEARER_TOKEN not found in environment for Download TLS Certificate") 
		}
 
		 if *force || tc.Validate(c) != nil {
			if *host == "" {
				return errors.New("TLS certificate setup: no SAN hostnames specified")
			}
			hosts := strings.Split(*host, ",")
	
			// validate host names
			for _, h := range hosts {
				valid_err := validation.ValidateHostname(h)
				if valid_err != nil {
					return valid_err
				}
			}
			key, cert, err := createTLSCert(tc, cmsBaseUrl, tc.CommonName, *host, bearerToken)
			if err != nil {
				return fmt.Errorf("TLS certificate setup: %v", err)
			}
			err = crypt.SavePrivateKeyAsPKCS8(key, tc.TLSKeyFile)
			if err != nil {
				return fmt.Errorf("TLS certificate setup: %v", err)
			} 
			err = ioutil.WriteFile(tc.TLSCertFile, cert, 0660)
			if err != nil {
				fmt.Println("Could not store TLS certificate")
				return fmt.Errorf("TLS certificate setup: %v", err)
			}
		 } else {
				 fmt.Println("TLS certificate already downloaded, skipping")
		 }           
		  return nil  
 }
 
 func (tc Download_Tls_Cert) Validate(c setup.Context) error {	 
	fmt.Fprintln(tc.ConsoleWriter, "Validating TLS certificate download setup...")	
	 _, err := os.Stat(tc.TLSCertFile)
	 if os.IsNotExist(err) {
		 return errors.New("TLSCertFile is not configured")
	 }
	 _, err = os.Stat(tc.TLSKeyFile)
	 if os.IsNotExist(err) {
		 return errors.New("TLSKeyFile is not configured")
	 }
	 return nil
  }