/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package validation

import (
	"crypto/x509"
	"errors"

	"strings"
	"net"
	"intel/isecl/cms/config"
	types "intel/isecl/lib/common/types/aas"
	log "github.com/sirupsen/logrus"
)

//ValidateCertificateRequest is used to validate the Certificate Signing Request
func ValidateCertificateRequest(conf *config.Configuration, csr *x509.CertificateRequest, certType string,
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
	cnTypeMapFromToken := make(map[string]string)

	for k,_  := range *ctxMap {
		params := strings.Split(k, ";")		
		if len(params) < 3 {
			cnSanMapFromToken[params[0]] = ""	
			cnTypeMapFromToken[params[0]] = params[1]	
		} else {
			cnSanMapFromToken[params[0]] = params[1]
			cnTypeMapFromToken[params[0]] = params[2]		
		}
		log.Info("Common Name in Token : " + params[0])		
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
	
	log.Info("Common Name in CSR : " + csr.Subject.String())		
	if sanlistFromToken, ok := cnSanMapFromToken[subjectFromCsr]; ok {
		log.Info("Got valid Common Name in CSR : " + csr.Subject.String())		
		if sanlistFromToken != "" {
			sans := strings.Split(sanlistFromToken, "=")
			if len(sans) > 1 {	
				tokenSanList := strings.Split(sans[1], ",")	
				for _, san := range tokenSanList {				
					if !ipInSlice(san, csr.IPAddresses) && !stringInSlice(san, csr.DNSNames) {
						log.Errorf("No role associated with provided SAN list in CSR")		
						return errors.New("No role associated with provided SAN list in CSR")
					}
				}		
			}					
			log.Info(sanlistFromToken)
		}
	} else {
		log.Errorf("No role associated with provided Common Name in CSR")		
		return errors.New("No role associated with provided Common Name in CSR")
	}

	if certTypeFromToken, _ := cnTypeMapFromToken[subjectFromCsr]; !strings.EqualFold("CERTTYPE=" + certType, certTypeFromToken) {
		log.Errorf("No role associated with provided Certificate Type in request - " + certType)
		return errors.New("No role associated with provided Certificate Type")
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
	// TODO: Enable validation
	if !foundBasicConstraints {
		log.Errorf("Basic constraints extension not found in CSR")
		//return errors.New("Basic constraints extension not found in CSR")
	}
	if !foundKeyUsage {
		log.Errorf("Key Usage extension not found in CSR")
		//return errors.New("Key Usage extension not found in CSR")
	} else if noOfLoops == len(validKeyUsageValue) {
		log.Errorf("Valid key usage not found in CSR")
		//return errors.New("Valid key usage not found in CSR")
	}
	return nil
}


func stringInSlice(str string, list []string) bool {
	for _, v := range list {
		if strings.EqualFold(v,str) {
			return true
		}
	}
	return false
}


func ipInSlice(h string, list []net.IP) bool {
	for _, v := range list {
		if ip := net.ParseIP(h); ip != nil {		
			if strings.EqualFold(v.String(), h) {
				return true
			}
		}
	}
	return false
}