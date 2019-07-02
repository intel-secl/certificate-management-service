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
	 "intel/isecl/cms/libcommon/crypt"
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

 var RootCertificateTemplate = x509.Certificate{	
	Subject: pkix.Name{
		CommonName:   constants.DefaultRootCACommonName,
	},
	Issuer: pkix.Name{
		CommonName: constants.DefaultRootCACommonName,
	},
	NotBefore: time.Now(),

	KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	BasicConstraintsValid: true,
	IsCA:                  true,
 }

 func getRootCACertTemplate(ca Root_Ca, pubKey crypto.PublicKey) (caCertTemplate x509.Certificate, err error) {	
	var serialNumber = big.NewInt(0)
	err = utils.WriteSerialNumber(serialNumber)
	if err != nil {
		return RootCertificateTemplate, err
	}
	RootCertificateTemplate.SerialNumber = serialNumber

	RootCertificateTemplate.SignatureAlgorithm, err = crypt.GetSignatureAlgorithm(pubKey)
	if err != nil {
		return RootCertificateTemplate, err
	}

	certValidity := ca.Config.CACertValidity
	if certValidity == 0 {		
		certValidity = constants.DefaultCACertValidiy
	}
	RootCertificateTemplate.NotAfter = time.Now().AddDate(certValidity, 0, 0)
	
	if ca.Config.Organization != "" {
		RootCertificateTemplate.Subject.Organization = append(RootCertificateTemplate.Subject.Organization, ca.Config.Organization)
	} else {
		RootCertificateTemplate.Subject.Organization = append(RootCertificateTemplate.Subject.Organization, constants.DefaultOrganization)
	}

	if ca.Config.Country != "" {
		RootCertificateTemplate.Subject.Country = append(RootCertificateTemplate.Subject.Country, ca.Config.Country)
	} else {
		RootCertificateTemplate.Subject.Country = append(RootCertificateTemplate.Subject.Country, constants.DefaultCountry)
	}

	if ca.Config.Province != "" {
		RootCertificateTemplate.Subject.Province = append(RootCertificateTemplate.Subject.Province, ca.Config.Province)
	} else {
		RootCertificateTemplate.Subject.Province = append(RootCertificateTemplate.Subject.Province, constants.DefaultProvince)
	}

	if ca.Config.Locality != "" {
		RootCertificateTemplate.Subject.Locality = append(RootCertificateTemplate.Subject.Locality, ca.Config.Locality)
	} else {
		RootCertificateTemplate.Subject.Locality = append(RootCertificateTemplate.Subject.Locality, constants.DefaultLocality)
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
 

 func (ca Root_Ca) Run(c setup.Context) error {
	 fmt.Fprintln(ca.ConsoleWriter, "Running Root CA setup...")
	 fs := flag.NewFlagSet("root_ca", flag.ContinueOnError)
	 force := fs.Bool("force", false, "force recreation, will overwrite any existing Root CA keys")

	 err := fs.Parse(ca.Flags)
	 if err != nil {
		 return err
	 }
	if *force || ca.Validate(c) != nil {
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
			return fmt.Errorf("Root CA setup: %v", err)
		}
		err = crypt.SavePemCert(cert, constants.RootCACertPath)			
		 if err != nil {
			return fmt.Errorf("Root CA setup: %v", err)
		}

		//store SHA384 of ROOT CA for further use
		rootCACertificateBytes, err := ioutil.ReadFile(constants.RootCACertPath)
		if err != nil {
			return fmt.Errorf("Root CA setup: %v", err)
		}
		caDigest, err := crypt.GetCertHashFromPemInHex(rootCACertificateBytes, crypto.SHA384)
		if err != nil {
			return fmt.Errorf("Root CA setup: %v", err)
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
 