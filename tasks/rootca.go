/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
 package tasks

 import (
	 "crypto/rand"
	 "crypto"
	 "crypto/x509"
	 "crypto/x509/pkix"
	 "errors"
	 "flag"
	 "fmt"
	 "intel/isecl/lib/common/setup"
	 "intel/isecl/cms/utils"
	 "intel/isecl/cms/config"
	 "intel/isecl/cms/constants"
	 "intel/isecl/lib/common/crypt"
	 "io"
	 "io/ioutil"
	 "os"
	 "time"	 
 )
 
 type Root_Ca struct {
	 Flags            []string
	 ConsoleWriter    io.Writer
	 Config           *config.Configuration
 }

 func GetCACertDefaultTemplate(cfg *config.Configuration, cn string, parent string) (x509.Certificate, error) {
	tmplt := x509.Certificate{
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string {cfg.Organization},
			Country:      []string {cfg.Country},
			Province:     []string {cfg.Province},
			Locality:     []string {cfg.Locality},
		},
		Issuer: pkix.Name{
			CommonName: parent,
		},
		NotBefore: time.Now(),
		NotAfter: time.Now().AddDate(cfg.CACertValidity, 0, 0),

		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	 };
	 serialNumber, err := utils.GetNextSerialNumber()
	 tmplt.SerialNumber = serialNumber
	 return tmplt, err
 }

 func getCACertTemplate(cfg *config.Configuration, cn string, parCn string,  pubKey crypto.PublicKey, ) (x509.Certificate, error) {
	tmplt, err := GetCACertDefaultTemplate(cfg, cn, parCn)
	if err != nil {
		return tmplt, err
	}

	tmplt.SignatureAlgorithm, err = crypt.GetSignatureAlgorithm(pubKey)
	if err != nil {
		return tmplt, err
	}
	return tmplt, err
}

 func createRootCACert(cfg *config.Configuration) (privKey crypto.PrivateKey, cert []byte, err error) {
	privKey, pubKey, err := crypt.GenerateKeyPair(cfg.KeyAlgorithm, cfg.KeyAlgorithmLength)
	if err != nil {
		return nil, nil, err
	}
	caCertTemplate, err := getCACertTemplate(cfg,
								constants.GetCaAttribs(constants.Root).CommonName,
								constants.GetCaAttribs(constants.Root).CommonName,
								pubKey)
	if err != nil {
		return nil, nil, err
	}
	cert, err = x509.CreateCertificate(rand.Reader, &caCertTemplate, &caCertTemplate, pubKey, privKey)
	if err != nil {
		return nil, nil, err
	}
	return 
 }
 
func updateConfig(cfg *config.Configuration, c setup.Context) (err error){
	cfg.CACertValidity, err = c.GetenvInt("CMS_CA_CERT_VALIDITY", "Certificate Management Service Root Certificate Validity")
	if err != nil {
		cfg.CACertValidity = constants.DefaultCACertValidiy
	} 

	cfg.Organization, err = c.GetenvString("CMS_CA_ORGANIZATION", "Certificate Management Service Root Certificate Organization")
	if err != nil {
		cfg.Organization = constants.DefaultOrganization
	}

	cfg.Locality, err = c.GetenvString("CMS_CA_LOCALITY", "Certificate Management Service Root Certificate Locality")
	if err != nil {
		cfg.Locality = constants.DefaultLocality
	}

	cfg.Province, err = c.GetenvString("CMS_CA_PROVINCE", "Certificate Management Service Root Certificate Province")
	if err != nil {
		cfg.Province = constants.DefaultProvince
	} 

	cfg.Country, err = c.GetenvString("CMS_CA_COUNTRY", "Certificate Management Service Root Certificate Country")
	if err != nil {
		cfg.Country = constants.DefaultCountry
	} 

	cfg.Save()
	return nil
}

 func (ca Root_Ca) Run(c setup.Context) error {
	 fmt.Fprintln(ca.ConsoleWriter, "Running Root CA setup...")
	 fs := flag.NewFlagSet("root_ca", flag.ContinueOnError)
	 force := fs.Bool("force", false, "force recreation, will overwrite any existing Root CA keys")

	 err := fs.Parse(ca.Flags)
	 if err != nil {
		 return err
	 }
	if *force || ca.Validate(c) != nil {
		 _ = updateConfig(ca.Config, c)
	 	 privKey, cert, err := createRootCACert(ca.Config)
		 if err != nil {
			 return fmt.Errorf("Root CA setup: %v", err)
		 }
		 key, err := x509.MarshalPKCS8PrivateKey(privKey)
		 if err != nil {
	 		 return fmt.Errorf("Could not marshal private key to pkcs8 format error :%s", err)
		 }
		 
		 //Store key and certificate
		 err = crypt.SavePrivateKeyAsPKCS8(key, constants.RootCAKeyPath)
		 if err != nil {
			return fmt.Errorf("Root CA setup: 1 %v", err)
		}
		err = crypt.SavePemCert(cert, constants.RootCACertPath)			
		 if err != nil {
			return fmt.Errorf("Root CA setup: 2 %v", err)
		}

		//store SHA384 of ROOT CA for further use
		rootCACertificateBytes, err := ioutil.ReadFile(constants.RootCACertPath)
		if err != nil {
			return fmt.Errorf("Root CA setup: 3 %v", err)
		}
		caDigest, err := crypt.GetCertHashFromPemInHex(rootCACertificateBytes, crypto.SHA384)
		if err != nil {
			return fmt.Errorf("Root CA setup: 4 %v", err)
		}
		ca.Config.RootCACertDigest = caDigest
		fmt.Println("Root CA Certificate Digest : ", caDigest)
	 } else {
		 fmt.Println("Root CA already configured, skipping")
	 }
	 return nil
 }
 
 func (ca Root_Ca) Validate(c setup.Context) error {
	 _, err := os.Stat(constants.RootCACertPath)	 
	 if os.IsNotExist(err) {
		 return errors.New("RootCACertFile is not configured")
	 }
	 _, err = os.Stat(constants.RootCAKeyPath)
	 if os.IsNotExist(err) {
		 return errors.New("RootCAKeyFile is not configured")
	 }
	 return nil
 }
 
