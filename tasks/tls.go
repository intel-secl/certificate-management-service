/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
 package tasks

 import (
	 "crypto/rand"
	 "crypto/x509"
	 "crypto/tls"
	 "errors"
	 "flag"
	 "fmt"
	 "intel/isecl/lib/common/setup"
	 "intel/isecl/lib/common/validation"
	 "intel/isecl/lib/common/crypt"
	 "intel/isecl/cms/config"
	 "intel/isecl/cms/constants"
	 "intel/isecl/cms/utils"
	 "io"
	 "net"
	 "os"
	 "strings"
	 "time"
 )
 
 // Should move this to lib common, as it is duplicated across CMS and TDA
 
 type TLS struct {
	 Flags           []string
	 ConsoleWriter   io.Writer
	 Config          *config.Configuration	
 }
 
 func outboundHost() (string, error) {
	 conn, err := net.Dial("udp", "1.1.1.1:80")
	 if err != nil {
		 return os.Hostname()
	 }
	 defer conn.Close()
 
	 return (conn.LocalAddr().(*net.UDPAddr)).IP.String(), nil
 }
 
 func createTLSCert(ts TLS, hosts string) (key []byte, cert []byte, err error) { 	 
	 csrData, key, err := crypt.CreateKeyPairAndCertificateRequest("CMS", hosts, ts.Config.KeyAlgorithm, ts.Config.KeyAlgorithmLength)
	 if err != nil {
		return nil, nil, err
	 }
	 
	 clientCSR, err := x509.ParseCertificateRequest(csrData)
    if err != nil {
		return nil, nil, err
	}
	
	serialNumber, err := utils.GetNextSerialNumber()
	 if err != nil {
		return nil, nil, err
	}

	 clientCRTTemplate := x509.Certificate{
        Signature:          clientCSR.Signature,
        SignatureAlgorithm: clientCSR.SignatureAlgorithm,

        PublicKeyAlgorithm: clientCSR.PublicKeyAlgorithm,
		PublicKey:          clientCSR.PublicKey,
		
		IPAddresses:        clientCSR.IPAddresses,
		DNSNames:           clientCSR.DNSNames,

        SerialNumber: serialNumber,
        Issuer:       RootCertificateTemplate.Issuer,
        Subject:      clientCSR.Subject,
        NotBefore:    time.Now(),
        NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageContentCommitment,
        ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	 }

	rootKeyPair, err := tls.LoadX509KeyPair(constants.RootCACertPath, constants.RootCAKeyPath)
	 if err != nil {
		 return
	 }
	cert, err = x509.CreateCertificate(rand.Reader, &clientCRTTemplate, &RootCertificateTemplate, clientCSR.PublicKey, rootKeyPair.PrivateKey)
    if err != nil {
        return nil, nil, err
    }
	 return
 }
 
 func (ts TLS) Run(c setup.Context) error {
	 fmt.Fprintln(ts.ConsoleWriter, "Running tls setup...")
	 fs := flag.NewFlagSet("tls", flag.ContinueOnError)
	 force := fs.Bool("force", false, "force recreation, will overwrite any existing tls keys")
	 defaultHostname, err := c.GetenvString("CMS_HOST_NAMES", "comma separated list of hostnames to add to TLS certificate")
	 if err != nil {
		 defaultHostname, _ = outboundHost()
	 }
	 host := fs.String("host_names", defaultHostname, "comma separated list of hostnames to add to TLS certificate")
 
	 err = fs.Parse(ts.Flags)
	 if err != nil {
		 return err
	 }
	 if *force || ts.Validate(c) != nil {
		 if *host == "" {
			 return errors.New("tls setup: no hostnames specified")
		 }
		 hosts := strings.Split(*host, ",")
 
		 // validate host names
		 for _, h := range hosts {
			 valid_err := validation.ValidateHostname(h)
			 if valid_err != nil {
				 return valid_err
			 }
		 }
		 
		 key, cert, err := createTLSCert(ts, *host)
		 if err != nil {
			 return fmt.Errorf("tls setup: %v", err)
		 }
		 err = crypt.SavePrivateKeyAsPKCS8(key, constants.TLSKeyPath)
		 if err != nil {
			return fmt.Errorf("tls setup: %v", err)
		}
		 err = crypt.SavePemCert(cert, constants.TLSCertPath)
		 if err != nil {
			return fmt.Errorf("tls setup: %v", err)
		}
	 } else {
		 fmt.Println("TLS already configured, skipping")
	 }
	 return nil
 }

 func (ts TLS) Validate(c setup.Context) error {	 
	fmt.Fprintln(ts.ConsoleWriter, "Validating tls setup...")
	 _, err := os.Stat(constants.TLSCertPath)
	 if os.IsNotExist(err) {
		 return errors.New("TLSCertFile is not configured")
	 }
	 _, err = os.Stat(constants.TLSKeyPath)
	 if os.IsNotExist(err) {
		 return errors.New("TLSKeyFile is not configured")
	 }
	 return nil
 }
 
