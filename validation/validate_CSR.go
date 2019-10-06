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
	 ctxMap *map[string]types.RoleInfo) error {

	// TODO: We should be able to support other signature algorithms... such as ECDSA with SHA384
	if csr.SignatureAlgorithm != x509.SHA384WithRSA {
		log.Errorf("Incorrect Signature Algorithm used (should be SHA 384 with RSA): %v", csr.SignatureAlgorithm)
		return errors.New("Incorrect Signature Algorithm used (should be SHA 384 with RSA)")
	}

	// Validate CN
	cnSanMapFromToken := make(map[string]string)
	cnTypeMapFromToken := make(map[string]string)

	// TODO: There is a problem here. We could have someone that has a role where the common name matches because they
	// want to obtain different type of certificates with the same common name. We are breaking out the loop below
	// when we find the first match with the common name. We should be looking for roles that matches the tuplet from CSR
	// common name, cert type and SAN List (if applicable). Need to re-order logic
	for k,_  := range *ctxMap {
		params := strings.Split(k, ";")		
		if len(params) < 3 {
			cnSanMapFromToken[params[0]] = ""	
			cnTypeMapFromToken[params[0]] = params[1]	
		} else {
			cnSanMapFromToken[params[0]] = params[1]
			cnTypeMapFromToken[params[0]] = params[2]		
		}
		log.Debug("Common Name in Token : " + params[0])		
	}
	subjectsFromCsr := strings.Split(csr.Subject.String(), ",")
	subjectFromCsr := ""
	for _,sub := range subjectsFromCsr {
		log.Debug(sub);
		if strings.Contains(sub, "CN=") {
			subjectFromCsr = sub			
			break
		}
	}
	
	log.Debug("Common Name in CSR : " + csr.Subject.String())		
	if sanlistFromToken, ok := cnSanMapFromToken[subjectFromCsr]; ok {
		log.Debug("Got valid Common Name in CSR : " + csr.Subject.String())		
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
			log.Debug(sanlistFromToken)
		}
	} else {
		log.Errorf("No role associated with provided Common Name in CSR")		
		return errors.New("No role associated with provided Common Name in CSR")
	}

	if certTypeFromToken, _ := cnTypeMapFromToken[subjectFromCsr]; !strings.EqualFold("CERTTYPE=" + certType, certTypeFromToken) {
		log.Errorf("No role associated with provided Certificate Type in request - " + certType)
		return errors.New("No role associated with provided Certificate Type")
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
