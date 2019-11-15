/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package validation

import (
	"crypto/x509"
	"fmt"
	"strings"
	"net"
	"intel/isecl/cms/config"
	"intel/isecl/cms/constants"
	"github.com/pkg/errors"
	types "intel/isecl/lib/common/types/aas"
	clog "intel/isecl/lib/common/log"
)
var log = clog.GetDefaultLogger()
var slog = clog.GetSecurityLogger()

//ValidateCertificateRequest is used to validate the Certificate Signing Request
func ValidateCertificateRequest(conf *config.Configuration, csr *x509.CertificateRequest, certType string,
	 ctxMap *map[string]types.RoleInfo) error {
	log.Trace("validation/validate_CSR:ValidateCertificateRequest() Entering")
	defer log.Trace("validation/validate_CSR:ValidateCertificateRequest() Leaving")

	// TODO: We should be able to support other signature algorithms... such as ECDSA with SHA384
	if csr.SignatureAlgorithm != x509.SHA384WithRSA {
		return fmt.Errorf("validation/validate_CSR:ValidateCertificateRequest() Incorrect Signature Algorithm used (should be SHA 384 with RSA): %v", csr.SignatureAlgorithm)
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
	// Validate CN
	sanListsFromToken := []string{}
	isCnPresentInToken := false

	for k,_  := range *ctxMap {
		params := strings.Split(k, ";")
		// Check if Subject matches with CN
		if len(params) > 0 && strings.EqualFold(params[0], subjectFromCsr) {
			isCnPresentInToken = true
			log.Debugf("validation/validate_CSR:ValidateCertificateRequest() Token contains required Common Name : %v ", subjectFromCsr)
			if len(params) > 2 {
				if strings.EqualFold(params[2], "CERTTYPE=" +certType) { // Check if cert type matches
					sanListsFromToken = append(sanListsFromToken, params[1])
				}
			}
		}
	}

	if(!isCnPresentInToken) {
		return errors.New("validation/validate_CSR:ValidateCertificateRequest() No role associated with provided Common Name in CSR -" + subjectFromCsr)
	}
	log.Info("validation/validate_CSR:ValidateCertificateRequest() Got valid Common Name in CSR : " + subjectFromCsr)

	// Validate SAN only for TLS
	if strings.EqualFold(constants.Tls, certType) || strings.EqualFold(constants.TlsClient, certType) {
		log.Debugf("validation/validate_CSR:ValidateCertificateRequest() San list(IP) requested in CSR - %v ", csr.IPAddresses)
		log.Debugf("validation/validate_CSR:ValidateCertificateRequest() San list(DNS) requested in CSR - %v ", csr.DNSNames)
		for _, sanlistFromToken := range sanListsFromToken {
			if sanlistFromToken != "" {
				log.Debugf("validation/validate_CSR:ValidateCertificateRequest() San list requested in token - %v ", sanlistFromToken)
				sans := strings.Split(sanlistFromToken, "=")
				if len(sans) > 1 {
					tokenSanList := strings.Split(sans[1], ",")
					isSanPresentInToken := true
					for _, san := range tokenSanList {
						if !ipInSlice(san, csr.IPAddresses) && !stringInSlice(san, csr.DNSNames) {
							isSanPresentInToken = false
							break;
						}
					}
					if(isSanPresentInToken) {
						log.Debugf("validation/validate_CSR:ValidateCertificateRequest() San list requested in CSR is part of Token is valid",)
						return nil
					}
				}
			}
		}
		return errors.New("validation/validate_CSR:ValidateCertificateRequest() No role associated with provided SAN list in CSR")
	}
	log.Info("validation/validate_CSR:ValidateCertificateRequest() Certificate Signing Request is valid")
	return nil
}


func stringInSlice(str string, list []string) bool {
	log.Trace("validation/validate_CSR:stringInSlice() Entering")
	defer log.Trace("validation/validate_CSR:stringInSlice() Leaving")
	for _, v := range list {
		if strings.EqualFold(v,str) {
			return true
		}
	}
	return false
}


func ipInSlice(h string, list []net.IP) bool {
	log.Trace("validation/validate_CSR:ipInSlice() Entering")
	defer log.Trace("validation/validate_CSR:ipInSlice() Leaving")
	for _, v := range list {
		if ip := net.ParseIP(h); ip != nil {		
			if strings.EqualFold(v.String(), h) {
				return true
			}
		}
	}
	return false
}
