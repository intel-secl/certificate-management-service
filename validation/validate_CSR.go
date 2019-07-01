/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package validation

import (
	"crypto/x509"
	"errors"

	"strings"
	"intel/isecl/cms/config"
	"intel/isecl/authservice/libcommon/types"
	log "github.com/sirupsen/logrus"
)

//ValidateCertificateRequest is used to validate the Certificate Signing Request
func ValidateCertificateRequest(conf *config.Configuration, csr *x509.CertificateRequest,
	 ctxMap *map[string]*types.RoleInfo) error {
	//var csrBytes []byte
	oidExtensionBasicConstraints := []int{2, 5, 29, 19}
	oidExtensionKeyUsage := []int{2, 5, 29, 15}

	/* Bitstring format for key extensions (IETF 3280) (MSB format)
			KeyUsage ::= BIT STRING {
	           digitalSignature        (0),
	           nonRepudiation          (1),
	           keyEncipherment         (2),
	           dataEncipherment        (3),
	           keyAgreement            (4),
	           keyCertSign             (5),
	           cRLSign                 (6),
	           encipherOnly            (7),
	           decipherOnly            (8) }
	*/
	//70 for rootCA certificate, 128 for JWT signing certificate, 160 for TLS certificate
	validKeyUsageValue := []int{70, 128, 160}
	foundBasicConstraints := false
	foundKeyUsage := false
	noOfLoops := 0

	if csr.SignatureAlgorithm != x509.SHA384WithRSA {
		log.Errorf("Incorrect Signature Algorithm used (should be SHA 384 with RSA): %v", csr.SignatureAlgorithm)
		return errors.New("Incorrect Signature Algorithm used (should be SHA 384 with RSA)")
	}

	// Validate CN
	cnSanMapFromToken := make(map[string]string)
	for k,_  := range *ctxMap {
		cnSans := strings.Split(k, ";")		
		if len(cnSans) < 2 {
			cnSanMapFromToken[cnSans[0]] = ""		
		} else {
			cnSanMapFromToken[cnSans[0]] = cnSans[1]		
		}
	}
	subjectsFromCsr := strings.Split(csr.Subject.String(), ",")
	subjectFromCsr := ""
	for _,sub := range subjectsFromCsr {
		log.Info(sub);
		if strings.Contains(sub, "CN=") {
			subjectFromCsr = sub			
			break
		}
	}
	
	if sanlistFromToken, ok := cnSanMapFromToken[subjectFromCsr]; ok {
		log.Info("Got valid Common Name in CSR : " + csr.Subject.String())		
		log.Info(sanlistFromToken)
	} else {
		log.Errorf("No role associated with provided Common Name in CSR")		
		return errors.New("No role associated with provided Common Name in CSR")
	}

	// Validate SAN list

	for _, extension := range csr.Extensions {
		if extension.Id.Equal(oidExtensionBasicConstraints) {
			foundBasicConstraints = true
		}
		//TODO: check if a component has permissions to use a certain key usage
		if extension.Id.Equal(oidExtensionKeyUsage) {
			foundKeyUsage = true
			for _, value := range validKeyUsageValue {
				if int(extension.Value[3]) != value {
					noOfLoops = noOfLoops + 1
					continue

				} else {
					break
				}

			}
		}
	}
	if !foundBasicConstraints {
		log.Errorf("Basic constraints extension not found in CSR")
		return errors.New("Basic constraints extension not found in CSR")
	}
	if !foundKeyUsage {
		log.Errorf("Key Usage extension not found in CSR")
		return errors.New("Key Usage extension not found in CSR")
	} else if noOfLoops == len(validKeyUsageValue) {
		log.Errorf("Valid key usage not found in CSR")
		return errors.New("Valid key usage not found in CSR")
	}
	return nil
}
