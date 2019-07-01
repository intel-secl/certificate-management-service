/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
 package tasks

 import (
	 "errors"
	 "flag"
	 "fmt"
	 "intel/isecl/lib/common/setup"
	 "intel/isecl/cms/libcommon/crypt"
	 "intel/isecl/cms/config"
	 "intel/isecl/cms/constants"
	 "io"
	 "os"
	 "encoding/pem"
	 jwtauth "intel/isecl/authservice/libcommon/jwt"
	 ct "intel/isecl/authservice/libcommon/types"
 )
 
 type Cms_Auth_Token struct {
	 Flags            []string
	 ConsoleWriter   io.Writer
	 Config          *config.Configuration	
 }

 
 func createCmsAuthToken(at Cms_Auth_Token, c setup.Context) ( err error) { 	 
	cert, key, err := crypt.CreateKeyPairAndCertificate("CMS JWT Signing", "", at.Config.KeyAlgorithm, at.Config.KeyAlgorithmLength)
	if err != nil {
	   return err
	}

	err = crypt.SavePrivateKeyAsPKCS8(key, constants.TrustedJWTSigningCertsDir + constants.TokenKeyFile)
	if err != nil {
	   return fmt.Errorf("jwt setup: %v", err)
   }
   certPemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert})
	err = crypt.SavePemCertWithShortSha1FileName(certPemBytes, constants.TrustedJWTSigningCertsDir)
	if err != nil {
	   return fmt.Errorf("jwt setup: %v", err)
   }
   fmt.Fprintln(at.ConsoleWriter, "Running CMS generate JWT token setup...")
	 factory, err := jwtauth.NewTokenFactory(key, true, certPemBytes, "CMS JWT Signing", 0)
	 if err != nil {
		 fmt.Println(err)
		 return err
	 }
	 at.Config.AasJwtCn, err = c.GetenvString("AAS_JWT_CN", "Authentication and Authorization JWT Common Name")
	if err != nil {
		at.Config.AasJwtCn = constants.DefaultAasJwtCn
	} 

	at.Config.AasTlsCn, err = c.GetenvString("AAS_TLS_CN", "Authentication and Authorization TLS Common Name")
	if err != nil {
		at.Config.AasTlsCn = constants.DefaultAasTlsCn
	} 

	at.Config.AasTlsSan, err = c.GetenvString("AAS_TLS_SAN", "Authentication and Authorization TLS SAN list")
	if err != nil {
		at.Config.AasTlsSan = constants.DefaultAasTlsSan
	} 

	 ur := []ct.RoleInfo {
		 ct.RoleInfo{"CMS",constants.CertApproverGroupName,"CN=" + at.Config.AasJwtCn}, 
		 ct.RoleInfo{"CMS",constants.CertApproverGroupName,"CN=" + at.Config.AasTlsCn + ";SAN=" + at.Config.AasTlsSan},
		}
	 claims := ct.RoleSlice{ur}
	 jwt, err := factory.Create(&claims,"CMS JWT Token", 0)
	 if err != nil {
		 fmt.Println(err)
		 return err
	 }
	 fmt.Println("\nJWT Token:",jwt)
	 return
 }
 
 func (at Cms_Auth_Token) Run(c setup.Context) error {
	 fmt.Fprintln(at.ConsoleWriter, "Running auth token setup...")
	 fs := flag.NewFlagSet("CmsAuthToken", flag.ContinueOnError)
	 force := fs.Bool("force", false, "force recreation, will overwrite any existing auth token")
 
	 err := fs.Parse(at.Flags)
	 if err != nil {
		 return err
	 }
	 if *force || at.Validate(c) != nil {
		 err := createCmsAuthToken(at, c)
		 if err != nil {
			 return fmt.Errorf("auth token setup: %v", err)
		 }
	 } else {
		 fmt.Println("Auth Token already configured, skipping")
	 }
	 return nil
 }
 
 func (at Cms_Auth_Token) Validate(c setup.Context) error {	 
	fmt.Fprintln(at.ConsoleWriter, "Validating auth token setup...")
	 _, err := os.Stat(constants.TrustedJWTSigningCertsDir + constants.TokenKeyFile)
	 if os.IsNotExist(err) {
		 return errors.New("Auth Token is not configured")
	 }
	 return nil
 }
 