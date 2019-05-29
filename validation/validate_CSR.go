/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package validation

import (
	"crypto/x509"
	"encoding/base64"

	log "github.com/sirupsen/logrus"
	//"strings"
	//"io/ioutil"
)

//ValidateCertificateRequest is used to validate the Certificate Signing Request
func ValidateCertificateRequest(csrInput string) bool {
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
	csrBase64Bytes, err := base64.StdEncoding.DecodeString(csrInput)
	if err != nil {
		log.Fatalf("Failed to read CSR: %s", err)
		return false
	}

	csr, err := x509.ParseCertificateRequest(csrBase64Bytes)
	if err != nil {
		log.Fatalf("Failed to parse CSR: %s", err)
		return false
	}

	if len(csr.Subject.Country) != 1 {
		log.Errorf("Incorrect Country name: %v", csr.Subject)
		return false
	}

	if len(csr.Subject.Province) != 1 {
		log.Errorf("Incorrect Province name: %v", csr.Subject)
		return false
	}

	if len(csr.Subject.Locality) != 1 {
		log.Errorf("Incorrect Locality name: %v", csr.Subject)
		return false
	}

	if len(csr.Subject.Organization) != 1 && csr.Subject.Organization[0] != "INTEL" {
		log.Errorf("Incorrect Organization name: %v", csr.Subject)
		return false
	}

	//TODO: Add the list of components whose  common names are whitelisted
	if csr.Subject.CommonName != "CMSCA" {
		log.Errorf("Incorrect Common name: %v", csr.Subject.CommonName)
		return false
	}

	if csr.SignatureAlgorithm != x509.SHA384WithRSA {
		log.Errorf("Incorrect Signature Algorithm used (should be SHA 384 with RSA): %v", csr.SignatureAlgorithm)
		return false
	}

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
		return false
	}
	if !foundKeyUsage {
		log.Errorf("Key Usage extension not found in CSR")
		return false
	} else if noOfLoops == len(validKeyUsageValue) {
		log.Errorf("Valid key usage not found in CSR")
		return false
	}
	return true
}
