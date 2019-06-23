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
	 "math/big"	 
	 "os"
	 "time"	 
 )
 
 type RootCa struct {
	 Flags            []string
	 RootCAKeyFile    string
	 RootCACertFile   string
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

 func getRootCACertTemplate(ca RootCa, pubKey crypto.PublicKey) (caCertTemplate x509.Certificate, err error) {	
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

 func createRootCACert(ca RootCa) (privKey crypto.PrivateKey, cert []byte, err error) {	
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
 

 func (ca RootCa) Run(c setup.Context) error {
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
		 err = crypt.SavePrivateKeyAsPKCS8(key, ca.RootCAKeyFile)
		 if err != nil {
			return fmt.Errorf("Root CA setup: %v", err)
		}
		err = crypt.SavePemCert(cert, ca.RootCACertFile)			
		 if err != nil {
			return fmt.Errorf("Root CA setup: %v", err)
		}
	 } else {
		 fmt.Println("Root CA already configured, skipping")
	 }
	 return nil
 }
 
 func (ca RootCa) Validate(c setup.Context) error {
	 _, err := os.Stat(ca.RootCACertFile)
	 if os.IsNotExist(err) {
		 return errors.New("RootCACertFile is not configured")
	 }
	 _, err = os.Stat(ca.RootCAKeyFile)
	 if os.IsNotExist(err) {
		 return errors.New("RootCAKeyFile is not configured")
	 }
	 return nil
 }
 