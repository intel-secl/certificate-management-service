/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
 package tasks

 import (
	 "crypto/rand"
	 "crypto/rsa"
	 "crypto/x509"
	 "crypto/x509/pkix"
	 "encoding/pem"
	 "errors"
	 "flag"
	 "fmt"
	 "intel/isecl/lib/common/setup"
	 "intel/isecl/cms/utils"
	 "intel/isecl/cms/config"
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
	SignatureAlgorithm: x509.SHA384WithRSA,
	Subject: pkix.Name{
		CommonName:   "CMSCA",
		Country:      []string{},
		Province:     []string{},
		Locality:     []string{},
		Organization: []string{},
	},
	Issuer: pkix.Name{
		CommonName: "CMSCA",
	},
	NotBefore: time.Now(),
	NotAfter:  time.Now().AddDate(5, 0, 0),

	KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	BasicConstraintsValid: true,
	IsCA:                  true,
 }

 func createRootCACert(ca RootCa) (key []byte, cert []byte, err error) {
	priv, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		return
	}
	key = x509.MarshalPKCS1PrivateKey(priv)
	if err != nil {
		return
	}

	var serialNumber = big.NewInt(0)
	err = utils.WriteSerialNumber(serialNumber)
	if err != nil {
		return
	}
	RootCertificateTemplate.SerialNumber = serialNumber

	certValidity := ca.Config.CACertValidity
	if certValidity == 0 {
		// Set to default
		certValidity = 5
	}
	RootCertificateTemplate.NotAfter = time.Now().AddDate(certValidity, 0, 0)

	if ca.Config.Organization != "" {
		RootCertificateTemplate.Subject.Organization = append(RootCertificateTemplate.Subject.Organization, ca.Config.Organization)
	} else {
		RootCertificateTemplate.Subject.Organization = append(RootCertificateTemplate.Subject.Organization, "INTEL")
	}

	if ca.Config.Country != "" {
		RootCertificateTemplate.Subject.Country = append(RootCertificateTemplate.Subject.Country, ca.Config.Country)
	} else {
		RootCertificateTemplate.Subject.Country = append(RootCertificateTemplate.Subject.Country, "US")
	}

	if ca.Config.Province != "" {
		RootCertificateTemplate.Subject.Province = append(RootCertificateTemplate.Subject.Province, ca.Config.Province)
	} else {
		RootCertificateTemplate.Subject.Province = append(RootCertificateTemplate.Subject.Province, "CA")
	}

	if ca.Config.Locality != "" {
		RootCertificateTemplate.Subject.Locality = append(RootCertificateTemplate.Subject.Locality, ca.Config.Locality)
	} else {
		RootCertificateTemplate.Subject.Province = append(RootCertificateTemplate.Subject.Locality, "SC")
	}

	cert, err = x509.CreateCertificate(rand.Reader, &RootCertificateTemplate, &RootCertificateTemplate, &priv.PublicKey, priv)
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
		 key, cert, err := createRootCACert(ca)
		 if err != nil {
			 return fmt.Errorf("Root CA setup: %v", err)
		 }
		 // marshal private key to disk
		 keyOut, err := os.OpenFile(ca.RootCAKeyFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0) // open file with restricted permissions
		 if err != nil {
			 return fmt.Errorf("Root CA setup: %v", err)
		 }
		 // private key should not be world readable
		 os.Chmod(ca.RootCAKeyFile, 0640)
		 defer keyOut.Close()
		 if err := pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY",  Bytes: key}); err != nil {
			 return fmt.Errorf("Root CA setup: %v", err)
		 }
		 // marshal cert to disk
		 certOut, err := os.OpenFile(ca.RootCACertFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0)
		 if err != nil {
			 return fmt.Errorf("Root CA setup: %v", err)
		 }
		 os.Chmod(ca.RootCACertFile, 0644)
		 defer certOut.Close()
		 if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: cert}); err != nil {
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
 