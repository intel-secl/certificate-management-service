/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
 package tasks

 import (
	 "flag"
	 "fmt"
	 "intel/isecl/lib/common/setup"
	 "intel/isecl/lib/common/crypt"
	 "intel/isecl/cms/config"
	 "intel/isecl/cms/constants"
	 "io"
	 "os"
	 "time"
	 "encoding/pem"
	 "github.com/pkg/errors"
	 jwtauth "intel/isecl/lib/common/jwt"
	 ct "intel/isecl/lib/common/types/aas"
 )
 
 type Cms_Auth_Token struct {
	 Flags            []string
	 ConsoleWriter   io.Writer
	 Config          *config.Configuration	
 }

 
 func createCmsAuthToken(at Cms_Auth_Token, c setup.Context) ( err error) {
	log.Trace("tasks/authtoken:createCmsAuthToken() Entering")
	defer log.Trace("tasks/authtoken:createCmsAuthToken() Leaving")

	cert, key, err := crypt.CreateKeyPairAndCertificate("CMS JWT Signing", "", constants.DefaultKeyAlgorithm, constants.DefaultKeyAlgorithmLength)
	if err != nil {
	   return errors.Wrap(err, "tasks/authtoken:createCmsAuthToken() Could not create CMS JWT certificate")			   
	}

	err = crypt.SavePrivateKeyAsPKCS8(key, constants.TrustedJWTSigningCertsDir + constants.TokenKeyFile)
	if err != nil {
	   return errors.Wrap(err, "tasks/authtoken:createCmsAuthToken() Could not save CMS JWT private key")			   
   }
   certPemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert})
	err = crypt.SavePemCertWithShortSha1FileName(certPemBytes, constants.TrustedJWTSigningCertsDir)
	if err != nil {
	   return errors.Wrap(err, "tasks/authtoken:createCmsAuthToken() Could not save CMS JWT certificate")			   
   }
   fmt.Fprintln(at.ConsoleWriter, "Running CMS generate JWT token setup...")

	 factory, err := jwtauth.NewTokenFactory(key, true, certPemBytes, "CMS JWT Signing", time.Duration(at.Config.TokenDurationMins) * time.Minute)
	 if err != nil {
		 return errors.Wrap(err, "tasks/authtoken:createCmsAuthToken() Could not get instance of Token factory")			   
	 }
	 at.Config.AasJwtCn, err = c.GetenvString("AAS_JWT_CN", "Authentication and Authorization JWT Common Name")
	if err != nil {
		at.Config.AasJwtCn = constants.DefaultAasJwtCn
	} 
	log.Infof("tasks/authtoken:Run() AAS setup JWT token common name - %v", at.Config.AasJwtCn)

	at.Config.AasTlsCn, err = c.GetenvString("AAS_TLS_CN", "Authentication and Authorization TLS Common Name")
	if err != nil {
		at.Config.AasTlsCn = constants.DefaultAasTlsCn
	} 
	log.Infof("tasks/authtoken:Run() AAS setup JWT token TLS common name - %v", at.Config.AasTlsCn)

	at.Config.AasTlsSan, err = c.GetenvString("AAS_TLS_SAN", "Authentication and Authorization TLS SAN list")
	if err != nil {
		at.Config.AasTlsSan = constants.DefaultAasTlsSan
	} 
	log.Infof("tasks/authtoken:Run() AAS setup JWT token TLS SAN - %v", at.Config.AasTlsSan)

	 ur := []ct.RoleInfo {
		 ct.RoleInfo{"CMS",constants.CertApproverGroupName,"CN=" + at.Config.AasJwtCn + ";CERTTYPE=JWT-Signing"}, 
		 ct.RoleInfo{"CMS",constants.CertApproverGroupName,"CN=" + at.Config.AasTlsCn + ";SAN=" + at.Config.AasTlsSan + ";CERTTYPE=TLS"},
		}
	 claims := ct.RoleSlice{ur}
	 
	 log.Infof("tasks/authtoken:Run() AAS setup JWT token claims - %v", claims)
	 jwt, err := factory.Create(&claims,"CMS JWT Token", 0)
	 if err != nil {
		 return errors.Wrap(err, "tasks/authtoken:createCmsAuthToken() Could not create CMS JWT token")			   
	 }
	 at.Config.Save();
	 fmt.Println("\nJWT Token:",jwt)
	 return
 }
 
 func (at Cms_Auth_Token) Run(c setup.Context) error {
	 log.Trace("tasks/authtoken:Run() Entering")
	 defer log.Trace("tasks/authtoken:Run() Leaving")

	 fmt.Fprintln(at.ConsoleWriter, "Running auth token setup...")
	 fs := flag.NewFlagSet("CmsAuthToken", flag.ContinueOnError)
	 force := fs.Bool("force", false, "force recreation, will overwrite any existing auth token")
 
	 err := fs.Parse(at.Flags)
	 if err != nil {
		 return errors.Wrap(err, "tasks/authtoken:Run() Could not parse input flags")	   
	 }
	 if *force || at.Validate(c) != nil {
		 err := createCmsAuthToken(at, c)
		 if err != nil {
			 return errors.Wrap(err, "tasks/authtoken:Run() Could not create CMS JWT token")			 
		 }
	 } else {
		 fmt.Println("Auth Token already configured, skipping")
	 }
	 return nil
 }
 
 func (at Cms_Auth_Token) Validate(c setup.Context) error {
	log.Trace("tasks/authtoken:Validate() Entering")
	defer log.Trace("tasks/authtoken:Validate() Leaving")

	fmt.Fprintln(at.ConsoleWriter, "Validating auth token setup...")
	 _, err := os.Stat(constants.TrustedJWTSigningCertsDir + constants.TokenKeyFile)
	 if os.IsNotExist(err) {
		 return errors.Wrap(err, "tasks/authtoken:Validate() Auth Token is not configured")
	 }
	 return nil
 }
 
