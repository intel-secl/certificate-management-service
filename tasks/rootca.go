/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
 package tasks

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"flag"
	"fmt"
	"github.com/pkg/errors"
	"intel/isecl/cms/v3/config"
	"intel/isecl/cms/v3/constants"
	"intel/isecl/cms/v3/utils"
	"intel/isecl/lib/common/v3/crypt"
	clog "intel/isecl/lib/common/v3/log"
	"intel/isecl/lib/common/v3/setup"
	"io"
	"os"
	"time"
)
 var log = clog.GetDefaultLogger()
 var slog = clog.GetSecurityLogger()

 type Root_Ca struct {
	 Flags            []string
	 ConsoleWriter    io.Writer
	 Config           *config.Configuration
 }

 func GetCACertDefaultTemplate(cfg *config.Configuration, cn string, parent string) (x509.Certificate, error) {
	log.Trace("tasks/rootca:GetCACertDefaultTemplate() Entering")
	defer log.Trace("tasks/rootca:GetCACertDefaultTemplate() Leaving")

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
	 return tmplt, errors.Wrap(err, "tasks/rootca:GetCACertDefaultTemplate() Could not get next serial number for certificate")
 }

 func getCACertTemplate(cfg *config.Configuration, cn string, parCn string,  pubKey crypto.PublicKey, ) (x509.Certificate, error) {
	log.Trace("tasks/rootca:getCACertTemplate() Entering")
	defer log.Trace("tasks/rootca:getCACertTemplate() Leaving")

	tmplt, err := GetCACertDefaultTemplate(cfg, cn, parCn)
	if err != nil {
		return tmplt, errors.Wrap(err, "tasks/rootca:getCACertTemplate() Could not get CA template")
	}

	tmplt.SignatureAlgorithm, err = crypt.GetSignatureAlgorithm(pubKey)
	if err != nil {
		return tmplt, errors.Wrap(err, "tasks/rootca:getCACertTemplate() Could not read signature from Public Key")
	}
	return tmplt, err
}

 func createRootCACert(cfg *config.Configuration) (privKey crypto.PrivateKey, cert []byte, err error) {
	log.Trace("tasks/rootca:createRootCACert() Entering")
	defer log.Trace("tasks/rootca:createRootCACert() Leaving")

	privKey, pubKey, err := crypt.GenerateKeyPair(constants.DefaultKeyAlgorithm, constants.DefaultKeyAlgorithmLength)
	if err != nil {
		return nil, nil, errors.Wrap(err, "tasks/rootca:createRootCACert() Could not create root key pair")
	}
	caCertTemplate, err := getCACertTemplate(cfg,
								constants.GetCaAttribs(constants.Root).CommonName,
								constants.GetCaAttribs(constants.Root).CommonName,
								pubKey)
	if err != nil {
		return nil, nil, errors.Wrap(err, "tasks/rootca:createRootCACert() Could not create CA certificate template")
	}
	cert, err = x509.CreateCertificate(rand.Reader, &caCertTemplate, &caCertTemplate, pubKey, privKey)
	if err != nil {
		return nil, nil, errors.Wrap(err, "tasks/rootca:createRootCACert() Could not create CA certificate")
	}
	return 
 }
 
func updateConfig(cfg *config.Configuration, c setup.Context) (err error){
	log.Trace("tasks/rootca:updateConfig() Entering")
	defer log.Trace("tasks/rootca:updateConfig() Leaving")

	cfg.CACertValidity, err = c.GetenvInt("CMS_CA_CERT_VALIDITY", "Certificate Management Service Root Certificate Validity")
	if err != nil {
		cfg.CACertValidity = constants.DefaultCACertValidiy
	} 
	log.Infof("tasks/rootca:updateConfig() CA certificate validity - %v", cfg.CACertValidity)

	cfg.Organization, err = c.GetenvString("CMS_CA_ORGANIZATION", "Certificate Management Service Root Certificate Organization")
	if err != nil {
		cfg.Organization = constants.DefaultOrganization
	}
	log.Infof("tasks/rootca:updateConfig() CA certificate organization - %v", cfg.Organization)

	cfg.Locality, err = c.GetenvString("CMS_CA_LOCALITY", "Certificate Management Service Root Certificate Locality")
	if err != nil {
		cfg.Locality = constants.DefaultLocality
	}
	log.Infof("tasks/rootca:updateConfig() CA certificate locality - %v", cfg.Locality)

	cfg.Province, err = c.GetenvString("CMS_CA_PROVINCE", "Certificate Management Service Root Certificate Province")
	if err != nil {
		cfg.Province = constants.DefaultProvince
	} 
	log.Infof("tasks/rootca:updateConfig() CA certificate province - %v", cfg.Province)

	cfg.Country, err = c.GetenvString("CMS_CA_COUNTRY", "Certificate Management Service Root Certificate Country")
	if err != nil {
		cfg.Country = constants.DefaultCountry
	} 
	log.Infof("tasks/rootca:updateConfig() CA certificate country - %v", cfg.Country)

	cfg.Save()
	return nil
}

 func (ca Root_Ca) Run(c setup.Context) error {
	log.Trace("tasks/rootca:Run() Entering")
	defer log.Trace("tasks/rootca:Run() Leaving")

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
			 return errors.Wrap(err, "tasks/rootca:Run() Could not create root certificate")
		 }
		 key, err := x509.MarshalPKCS8PrivateKey(privKey)
		 if err != nil {
	 		 return errors.Wrap(err, "tasks/rootca:Run() Could not marshal private key to pkcs8 format error")
		 }
		 
		 //Store key and certificate
		 err = crypt.SavePrivateKeyAsPKCS8(key, constants.RootCAKeyPath)
		 if err != nil {
			return errors.Wrap(err, "tasks/rootca:Run() Could not save root private key")
		}
		err = crypt.SavePemCert(cert, constants.RootCACertPath)			
		 if err != nil {
			return errors.Wrap(err, "tasks/rootca:Run() Could not save root certificate")
		}
	 } else {
		 fmt.Println("Root CA already configured, skipping")
	 }
	 return nil
 }
 
 func (ca Root_Ca) Validate(c setup.Context) error {
	log.Trace("tasks/rootca:Validate() Entering")
	defer log.Trace("tasks/rootca:Validate() Leaving")

	 _, err := os.Stat(constants.RootCACertPath)	 
	 if os.IsNotExist(err) {
		 return errors.Wrap(err, "tasks/rootca:Validate() RootCACertFile is not configured")
	 }
	 _, err = os.Stat(constants.RootCAKeyPath)
	 if os.IsNotExist(err) {
		 return errors.Wrap(err, "tasks/rootca:Validate() RootCAKeyFile is not configured")
	 }
	 return nil
 }
 
