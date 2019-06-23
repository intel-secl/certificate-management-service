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
	 jwtauth "intel/isecl/cms/libcommon/jwt"
	 ct "intel/isecl/authservice/libcommon/types"
 )
 
 // Should move this to lib common, as it is duplicated across CMS and TDA
 
 type AuthCert struct {
	 Flags            []string
	 ConsoleWriter   io.Writer
	 Config          *config.Configuration	
 }

 
 func createAuthCert(at AuthCert) ( err error) { 	 
	cert, key, err := crypt.CreateKeyPairAndCertificate("CMS JWT Signing", "127.0.0.1", at.Config.KeyAlgorithm, at.Config.KeyAlgorithmLength)
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
	 ur := []ct.UserRole {ct.UserRole{"CMS","CertificateRequester","CN:AAS"}}
	 claims := ct.UserRoles{ur}
	 fmt.Println(claims)
	 jwt, err := factory.Create(&claims,"Setup JWT for AAS", 0)
	 if err != nil {
		 fmt.Println(err)
		 return err
	 }
	 fmt.Println("\nJWT :",jwt)
	 fmt.Printf("\n\n Token Generation Complete. Testing Token verification and retrieving claims\n\n")
	 return
 }
 
 func (at AuthCert) Run(c setup.Context) error {
	 fmt.Fprintln(at.ConsoleWriter, "Running auth token setup...")
	 fs := flag.NewFlagSet("AuthCert", flag.ContinueOnError)
	 force := fs.Bool("force", false, "force recreation, will overwrite any existing auth token")
 
	 err := fs.Parse(at.Flags)
	 if err != nil {
		 return err
	 }
	 if *force || at.Validate(c) != nil {
		 err := createAuthCert(at)
		 if err != nil {
			 return fmt.Errorf("auth token setup: %v", err)
		 }
	 } else {
		 fmt.Println("Auth Token already configured, skipping")
	 }
	 return nil
 }
 
 func (at AuthCert) Validate(c setup.Context) error {
	 _, err := os.Stat(constants.TrustedJWTSigningCertsDir + constants.TokenKeyFile)
	 if os.IsNotExist(err) {
		 return errors.New("Auth Token is not configured")
	 }
	 return nil
 }
 