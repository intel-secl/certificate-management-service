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
	 "math/big"	 
	 "os"
	 "time"	 
 )
 
 type Root_Ca struct {
	 Flags            []string
	 ConsoleWriter    io.Writer
	 Config           *config.Configuration
 }


 func GetRootCACertDefaultTemplate(config *config.Configuration) (RootCertificateTemplate x509.Certificate) {
	return x509.Certificate{	
		Subject: pkix.Name{
			CommonName:   constants.DefaultRootCACommonName,
			Organization: []string {config.Organization},
			Country:      []string {config.Country},
			Province:     []string {config.Province},
			Locality:     []string {config.Locality},
		},
		Issuer: pkix.Name{
			CommonName: constants.DefaultRootCACommonName,
		},
		NotBefore: time.Now(),
		NotAfter: time.Now().AddDate(config.CACertValidity, 0, 0),

		SerialNumber:          big.NewInt(0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	 };
 }

 func getRootCACertTemplate(ca Root_Ca, pubKey crypto.PublicKey) (caCertTemplate x509.Certificate, err error) {	
	RootCertificateTemplate := GetRootCACertDefaultTemplate(ca.Config);	
	err = utils.WriteSerialNumber(RootCertificateTemplate.SerialNumber)
	if err != nil {
		return RootCertificateTemplate, err
	}

	RootCertificateTemplate.SignatureAlgorithm, err = crypt.GetSignatureAlgorithm(pubKey)
	if err != nil {
		return RootCertificateTemplate, err
	}
	return RootCertificateTemplate, err
}

 func createRootCACert(ca Root_Ca) (privKey crypto.PrivateKey, cert []byte, err error) {	
	privKey, pubKey, err := crypt.GenerateKeyPair(ca.Config.KeyAlgorithm, ca.Config.KeyAlgorithmLength)
	if err != nil {
		return nil, nil, err
	}
	caCertTemplate, err := getRootCACertTemplate(ca, pubKey)
	if err != nil {
		return nil, nil, err
	}
	cert, err = x509.CreateCertificate(rand.Reader, &caCertTemplate, &caCertTemplate, pubKey, privKey)
	if err != nil {
		return nil, nil, err
	}
	return 
 }
 
func updateConfig(s Root_Ca, c setup.Context) (err error){
	s.Config.CACertValidity, err = c.GetenvInt("CMS_CA_CERT_VALIDITY", "Certificate Management Service Root Certificate Validity")
	if err != nil {
		s.Config.CACertValidity = constants.DefaultCACertValidiy
	} 

	s.Config.Organization, err = c.GetenvString("CMS_CA_ORGANIZATION", "Certificate Management Service Root Certificate Organization")
	if err != nil {
		s.Config.Organization = constants.DefaultOrganization
	}

	s.Config.Locality, err = c.GetenvString("CMS_CA_LOCALITY", "Certificate Management Service Root Certificate Locality")
	if err != nil {
		s.Config.Locality = constants.DefaultLocality
	}

	s.Config.Province, err = c.GetenvString("CMS_CA_PROVINCE", "Certificate Management Service Root Certificate Province")
	if err != nil {
		s.Config.Province = constants.DefaultProvince
	} 

	s.Config.Country, err = c.GetenvString("CMS_CA_COUNTRY", "Certificate Management Service Root Certificate Country")
	if err != nil {
		s.Config.Country = constants.DefaultCountry
	} 

	s.Config.Save()
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
		 _ = updateConfig(ca, c)
	 	 privKey, cert, err := createRootCACert(ca)
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
 
