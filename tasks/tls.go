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
	 "github.com/pkg/errors"
	 "flag"
	 "fmt"
	 "intel/isecl/lib/common/v2/setup"
	 "intel/isecl/lib/common/v2/validation"
	 "intel/isecl/lib/common/v2/crypt"
	 "intel/isecl/cms/v2/config"
	 "intel/isecl/cms/v2/constants"
	 "intel/isecl/cms/v2/utils"
	 "io"
	 "io/ioutil"
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
	 log.Trace("tasks/tls:outboundHost() Entering")
	 defer log.Trace("tasks/tls:outboundHost() Leaving")

	 conn, err := net.Dial("udp", "1.1.1.1:80")
	 if err != nil {
		 return os.Hostname()
	 }
	 defer conn.Close()
 
	 return (conn.LocalAddr().(*net.UDPAddr)).IP.String(), nil
 }
 
 func createTLSCert(ts TLS, hosts string, ca *x509.Certificate, caKey interface{}) (key []byte, cert []byte, err error) {
	 log.Trace("tasks/tls:createTLSCert() Entering")
	 defer log.Trace("tasks/tls:createTLSCert() Leaving")

	 csrData, key, err := crypt.CreateKeyPairAndCertificateRequest(pkix.Name{
		 Country:            []string{constants.DefaultCountry},
		 Organization:       []string{constants.DefaultOrganization},
		 Locality:           []string{constants.DefaultLocality},
		 Province:           []string{constants.DefaultProvince},
		 CommonName:         "CMS",
	 }, hosts, constants.DefaultKeyAlgorithm, constants.DefaultKeyAlgorithmLength)
	 if err != nil {
		return nil, nil, errors.Wrap(err, "tasks/tls:createTLSCert() Could not create CSR")
	 }
	 
	 clientCSR, err := x509.ParseCertificateRequest(csrData)
     if err != nil {
		return nil, nil, errors.Wrap(err, "tasks/tls:createTLSCert() Could not parse CSR")
	 }
	
	serialNumber, err := utils.GetNextSerialNumber()
	if err != nil {
		return nil, nil, errors.Wrap(err, "tasks/tls:createTLSCert() Could get next serial number")
	}

	 clientCRTTemplate := x509.Certificate{
        Signature:          clientCSR.Signature,
        SignatureAlgorithm: clientCSR.SignatureAlgorithm,

        PublicKeyAlgorithm: clientCSR.PublicKeyAlgorithm,
		PublicKey:          clientCSR.PublicKey,
		
		IPAddresses:        clientCSR.IPAddresses,
		DNSNames:           clientCSR.DNSNames,

        SerialNumber: serialNumber,
        Issuer:       ca.Issuer,
        Subject:      clientCSR.Subject,
        NotBefore:    time.Now(),
        NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageContentCommitment,
        ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	 }

	cert, err = x509.CreateCertificate(rand.Reader, &clientCRTTemplate, ca, clientCSR.PublicKey, caKey)
    if err != nil {
        return nil, nil, errors.Wrap(err, "tasks/tls:createTLSCert() Could not create certificate")
    }
	 return
 }
 
 func (ts TLS) Run(c setup.Context) error {
	 log.Trace("tasks/tls:Run() Entering")
	 defer log.Trace("tasks/tls:Run() Leaving")

	 fmt.Fprintln(ts.ConsoleWriter, "Running tls setup...")
	 fs := flag.NewFlagSet("tls", flag.ContinueOnError)
	 force := fs.Bool("force", false, "force recreation, will overwrite any existing tls keys")
	 defaultHostname, err := c.GetenvString("SAN_LIST", "comma separated list of hostnames to add to TLS certificate")
	 if err != nil {
		 defaultHostname, _ = outboundHost()
	 }
	 host := fs.String("host_names", defaultHostname, "comma separated list of hostnames to add to TLS certificate")
	 log.Infof("tasks/tls:Run() SAN list added to CMS TLS certificate - %v", host)

	 err = fs.Parse(ts.Flags)
	 if err != nil {
		 return errors.Wrap(err, "tasks/tls:Run() Could not parse input flags")
	 }
	 if *force || ts.Validate(c) != nil {
		 if *host == "" {
			 return errors.New("tasks/tls:Run() SAN list is empty for CMS TLS certificate")
		 }
		 hosts := strings.Split(*host, ",")
 
		 // validate host names
		 for _, h := range hosts {
			 valid_err := validation.ValidateHostname(h)
			 if valid_err != nil {
				 return errors.Wrap(valid_err, "tasks/tls:Run() Host name is not valid")
			 }
		 }

		 tlsCaAttr := constants.GetCaAttribs(constants.Tls)
		 tlsCaCert, tlsCaPrivKey, err := crypt.LoadX509CertAndPrivateKey(tlsCaAttr.CertPath, tlsCaAttr.KeyPath)
		 key, cert, err := createTLSCert(ts, *host, tlsCaCert, tlsCaPrivKey)
		 if err != nil {
			 return errors.Wrap(err, "tasks/tls:Run() Could not create TLS certificate")
		 }
		 err = crypt.SavePrivateKeyAsPKCS8(key, constants.TLSKeyPath)
		 if err != nil {
			return errors.Wrap(err, "tasks/tls:Run() Could not save TLS private key")
		}
		 // we need to store the TLS cert as a chain since Web server should send the
		 // entire certificate chain minus the root
		 err = crypt.SavePemCertChain(constants.TLSCertPath, cert, tlsCaCert.Raw)
		 if err != nil {
			return errors.Wrap(err, "tasks/tls:Run() Could not save TLS certificate")
		 }

		 tlsCertificateBytes, err := ioutil.ReadFile(constants.TLSCertPath)
		 if err != nil {
			 return errors.Wrap(err, "tasks/tls:Run() Could not read TLS cert")
		 }

		 tlsDigest, err := crypt.GetCertHashFromPemInHex(tlsCertificateBytes, crypto.SHA384)
		 if err != nil {
			 return errors.Wrap(err, "tasks/tls:Run() Unable to get digest of TLS certificate")
		 }
		 ts.Config.TlsCertDigest = tlsDigest
		 ts.Config.Save();
		 fmt.Println("TLS Certificate Digest : ", tlsDigest)
	 } else {
		 fmt.Println("TLS already configured, skipping")
	 }
	 return nil
 }

 func (ts TLS) Validate(c setup.Context) error {	 
	log.Trace("tasks/tls:Validate() Entering")
	defer log.Trace("tasks/tls:Validate() Leaving")

	fmt.Fprintln(ts.ConsoleWriter, "Validating tls setup...")
	 _, err := os.Stat(constants.TLSCertPath)
	 if os.IsNotExist(err) {
		 return errors.Wrap(err, "tasks/tls:Validate() TLSCertFile is not configured")
	 }
	 _, err = os.Stat(constants.TLSKeyPath)
	 if os.IsNotExist(err) {
		 return errors.Wrap(err, "tasks/tls:Validate() TLSCertFile is not configured")
	 }
	 return nil
 }
 
