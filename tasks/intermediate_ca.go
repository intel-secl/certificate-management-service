/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
 package tasks

import (
	"crypto/rand"
	"crypto"
	"crypto/x509"
	"flag"
	"fmt"
	"intel/isecl/lib/common/setup"
	"intel/isecl/cms/config"
	"intel/isecl/cms/constants"
	"intel/isecl/lib/common/crypt"
	"io"
	"os"
	"github.com/pkg/errors"
)

type Intermediate_Ca struct {
	Flags            []string
	ConsoleWriter    io.Writer
	Config           *config.Configuration
}

func createIntermediateCACert(cfg *config.Configuration, cn string) (privKey crypto.PrivateKey, cert []byte, err error) {
	log.Trace("tasks/intermediate_ca:createIntermediateCACert() Entering")
	defer log.Trace("tasks/intermediate_ca:createIntermediateCACert() Leaving")

	rCaAttr := constants.GetCaAttribs(constants.Root)

	privKey, pubKey, err := crypt.GenerateKeyPair(constants.DefaultKeyAlgorithm, constants.DefaultKeyAlgorithmLength)
	if err != nil {
		return nil, nil, errors.Wrap(err, "tasks/intermediate_ca:createIntermediateCACert() Could not generate Keypair")
	}
	caCertTemplate, err := getCACertTemplate(cfg, cn, rCaAttr.CommonName, pubKey)
	if err != nil {
		return nil, nil, errors.Wrap(err, "tasks/intermediate_ca:createIntermediateCACert() Could not generate Certificate Template")
	}
	
	rootCert, rootCAPrivKey, err := crypt.LoadX509CertAndPrivateKey(rCaAttr.CertPath, rCaAttr.KeyPath)
	if err != nil {
		return nil, nil, errors.Wrap(err, "tasks/intermediate_ca:createIntermediateCACert() Could not load root CA certificate")
	}

	cert, err = x509.CreateCertificate(rand.Reader, &caCertTemplate, rootCert, pubKey, rootCAPrivKey)
	if err != nil {
		return nil, nil, errors.Wrap(err, "tasks/intermediate_ca:createIntermediateCACert() Could not create certificate")
	}
	return
}

func (ca Intermediate_Ca) Run(c setup.Context) error {
	log.Trace("tasks/intermediate_ca:Run() Entering")
	defer log.Trace("tasks/intermediate_ca:Run() Leaving")

	fmt.Fprintln(ca.ConsoleWriter, "Running Intermediate CA setup...")
	fs := flag.NewFlagSet("intermediate_ca", flag.ContinueOnError)
	force := fs.Bool("force", false, "force recreation, will overwrite any existing Intermediate CA keys")

	var interCAType string
	fs.StringVar(&interCAType, "type", "", "type of intermediary ca")

	err := fs.Parse(ca.Flags)
	if err != nil {
		return errors.Wrap(err, "tasks/intermediate_ca:Run() Could not parse input flags")
	}

	// this represents the list of CAs that we will be creating. Start out with an empty list and then fill it out
	var cas []string

	// there were no specific type that was passed in ... so we will do all of them
	if (interCAType == "") {
		cas = constants.GetIntermediateCAs()
	} else {
		if attr := constants.GetCaAttribs(interCAType); attr.CommonName == "" {
			// the type passed in does not match with one of the supported intermediaries
			return errors.Wrap(err, "tasks/intermediate_ca:Run() could not find matching Intermediary Certificate. Please check help for list of Intermediary CAs supported")
		}
		cas = append(cas, interCAType)
	}

	for _, interCa := range cas{
		if *force || ca.Validate(c) != nil {
			log.Infof("tasks/intermediate_ca:Run() Creating intermediate CA - %v", interCa)
			caAttr := constants.GetCaAttribs(interCa)
			privKey, cert, err := createIntermediateCACert(ca.Config, caAttr.CommonName)
			if err != nil {
				return errors.Wrap(err, "tasks/intermediate_ca:Run() Could not create intemediate CA")
			}

			key, err := x509.MarshalPKCS8PrivateKey(privKey)
			if err != nil {
				 return errors.Wrap(err, "tasks/intermediate_ca:Run() Could not marshal private key to pkcs8 format error")
			}

			//Store key and certificate
			err = crypt.SavePrivateKeyAsPKCS8(key, caAttr.KeyPath)
			if err != nil {
			   return errors.Wrapf(err, "tasks/intermediate_ca:Run() -%v - Could not save private key", interCa)
		   }
		   err = crypt.SavePemCert(cert, caAttr.CertPath)
			if err != nil {
			   return errors.Wrapf(err, "tasks/intermediate_ca:Run() -%v - Could not save certificate", interCa)			   
		   }
		} else {
			fmt.Println(interCa, " Intermediate CA already configured, skipping")
		}
	}
	return nil
}

func (ca Intermediate_Ca) Validate(c setup.Context) error {
	log.Trace("tasks/intermediate_ca:Validate() Entering")
	defer log.Trace("tasks/intermediate_ca:Validate() Leaving")

	cas := constants.GetIntermediateCAs()
	for _, interCa := range cas{
		
		caAttr := constants.GetCaAttribs(interCa)

		_, err := os.Stat(caAttr.CertPath)	 
		if os.IsNotExist(err) {
			return errors.Wrapf(err, "tasks/intermediate_ca:Validate() -%v - Intermediary CA Certificate is not configured", interCa)
		}
		_, err = os.Stat(caAttr.CertPath)
		if os.IsNotExist(err) {
			return errors.Wrapf(err, "tasks/intermediate_ca:Validate() -%v - Intermediary CA Key is not configured", interCa)
		}
	}
	return nil
}
