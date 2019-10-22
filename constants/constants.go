/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package constants

import (
	"crypto"
	clog "intel/isecl/lib/common/log"
)
var log = clog.GetDefaultLogger()

const (
	ServiceName                    = "CMS"
	HomeDir                        = "/opt/cms/"
	ConfigDir                      = "/etc/cms/"
	ExecutableDir                  = "/opt/cms/bin/"
	ExecLinkPath                   = "/usr/bin/cms"
	RunDirPath                     = "/run/cms"
	LogDir                         = "/var/log/cms/"
	LogFile                        = LogDir + "cms.log"
	SecurityLogFile                = LogDir + "cms-security.log"
	HTTPLogFile                    = "http.log"
	ConfigFile                     = "config.yml"
	TokenKeyFile                   = "cms-jwt.key"
	TrustedJWTSigningCertsDir      = ConfigDir + "jwt/"
	RootCADirPath                  = ConfigDir + "root-ca/"
	RootCACertPath                 = RootCADirPath + "root-ca-cert.pem"
	RootCAKeyPath                  = ConfigDir + "root-ca.key"
	IntermediataCADirPath          = ConfigDir + "interimediate-ca/"
	TLSCertPath                    = ConfigDir + "tls-cert.pem"
	TLSKeyPath                     = ConfigDir + "tls.key"
	SerialNumberPath               = ConfigDir + "serial-number"
	TokenSignKeysAndCertDir        = ConfigDir + "certs/tokensign/"
	TokenSignKeyFile               = TokenSignKeysAndCertDir + "key.key"
	TokenSignCertFile              = TokenSignKeysAndCertDir + "jwtsigncert.pem"
	PIDFile                        = "cms.pid"
	ServiceRemoveCmd               = "systemctl disable cms"
	HashingAlgorithm               = crypto.SHA384
	PasswordRandomLength           = 20
	DefaultHeartbeatInt            = 5
	DefaultAuthDefendMaxAttempts   = 5
	DefaultAuthDefendIntervalMins  = 5
	DefaultAuthDefendLockoutMins   = 15
	DefaultSSLCertFilePath         = ConfigDir + "cms_cert.pem"
	DefaultRootCACommonName        = "CMSCA"
	DefaultPort                    = 8445
	DefaultOrganization            = "INTEL"
	DefaultCountry                 = "US"
	DefaultProvince                = "SF"
	DefaultLocality                = "SC"
	DefaultCACertValidiy           = 5
	DefaultKeyAlgorithm            = "rsa"
	DefaultKeyAlgorithmLength      = 3072
	CertApproverGroupName          = "CertApprover"
	DefaultAasJwtCn                = "AAS JWT Signing Certificate"
	DefaultAasTlsCn                = "AAS TLS Certificate"
	DefaultAasTlsSan               = "127.0.0.1,localhost"
	DefaultTokenDurationMins       = 240
	DefaultJwtValidateCacheKeyMins = 60
)

// State represents whether or not a daemon is running or not
type State bool

const (
	// Stopped is the default nil value, indicating not running
	Stopped State = false
	// Running means the daemon is active
	Running State = true
)

type CaAttrib struct {
	CommonName string
	CertPath   string
	KeyPath    string
}

const (
	Root      = "root"
	Tls       = "TLS"
	TlsClient = "TLS-Client"
	Signing   = "Signing"
)

var mp = map[string]CaAttrib{
	Root:      {"CMSCA", RootCADirPath + "root-ca-cert.pem", ConfigDir + "root-ca.key"},
	Tls:       {"CMS TLS CA", IntermediataCADirPath + "tls-ca.pem", IntermediataCADirPath + "tls-ca.key"},
	TlsClient: {"CMS TLS Client CA", IntermediataCADirPath + "tls-client-ca.pem", IntermediataCADirPath + "tls-client-ca.key"},
	Signing:   {"CMS Signing CA", IntermediataCADirPath + "signing-ca.pem", IntermediataCADirPath + "signing-ca.key"},
}

func GetIntermediateCAs() []string {
	log.Trace("constants/constants:GetIntermediateCAs() Entering")
	defer log.Trace("constants/constants:GetIntermediateCAs() Leaving")
	
	return []string{Tls, TlsClient, Signing}
}

func GetCaAttribs(t string) CaAttrib {
	log.Trace("constants/constants:GetCaAttribs() Entering")
	defer log.Trace("constants/constants:GetCaAttribs() Leaving")

	if val, found := mp[t]; found {
		return val
	}
	return CaAttrib{}
}
