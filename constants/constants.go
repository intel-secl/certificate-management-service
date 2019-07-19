/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package constants

import "crypto"

const (
	ServiceName                   = "CMS"
	HomeDir                       = "/opt/cms/"
	ConfigDir                     = "/etc/cms/"
	ExecutableDir                 = "/opt/cms/bin/"
	ExecLinkPath                  = "/usr/bin/cms"
	RunDirPath                    = "/run/cms"
	LogDir                        = "/var/log/cms/"
	LogFile                       = "cms.log"
	HTTPLogFile                   = "http.log"
	ConfigFile                    = "config.yml"
	TokenKeyFile                  = "cms-jwt-key.pem"
	TrustedJWTSigningCertsDir     = ConfigDir + "jwt/"
	RootCACertPath                = ConfigDir + "root-ca-cert.pem"
	RootCAKeyPath                 = ConfigDir + "root-ca-key.pem"
	TLSCertPath                   = ConfigDir + "tls-cert.pem"
	TLSKeyPath                    = ConfigDir + "tls-key.pem"
	SerialNumberPath              = ConfigDir + "serial-number"	
	TokenSignKeysAndCertDir       = ConfigDir + "certs/tokensign/"
	TokenSignKeyFile              = TokenSignKeysAndCertDir + "key.pem"
	TokenSignCertFile             = TokenSignKeysAndCertDir + "jwtsigncert.pem"
	PIDFile                       = "cms.pid"
	ServiceRemoveCmd              = "systemctl disable cms"
	HashingAlgorithm              = crypto.SHA384
	PasswordRandomLength          = 20
	DefaultHeartbeatInt           = 5
	DefaultAuthDefendMaxAttempts  = 5
	DefaultAuthDefendIntervalMins = 5
	DefaultAuthDefendLockoutMins  = 15
	DefaultSSLCertFilePath        = ConfigDir + "cms_cert.pem"
	DefaultRootCACommonName       = "CMSCA"
	DefaultPort                   = 8443
	DefaultOrganization           = "INTEL"
	DefaultCountry                = "US"
	DefaultProvince               = "CA"
	DefaultLocality               = "SC"
	DefaultCACertValidiy          = 5
	DefaultKeyAlgorithm           = "rsa"
	DefaultKeyAlgorithmLength     = 3072
	CertApproverGroupName         = "CertApprover"
	DefaultAasJwtCn               = "AAS JWT Signing Certificate"	
	DefaultAasTlsCn               = "AAS TLS Certificate"
	DefaultAasTlsSan              = "127.0.0.1,localhost"
	DefaultTokenDurationMins      = 240
)

// State represents whether or not a daemon is running or not
type State bool

const (
	// Stopped is the default nil value, indicating not running
	Stopped State = false
	// Running means the daemon is active
	Running State = true
)
