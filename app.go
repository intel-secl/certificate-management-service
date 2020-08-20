/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"intel/isecl/cms/v3/config"
	"intel/isecl/cms/v3/constants"
	"intel/isecl/cms/v3/resource"
	"intel/isecl/cms/v3/tasks"
	"intel/isecl/cms/v3/version"
	"intel/isecl/lib/common/v3/crypt"
	e "intel/isecl/lib/common/v3/exec"
	"intel/isecl/lib/common/v3/log/message"
	"intel/isecl/lib/common/v3/middleware"
	cos "intel/isecl/lib/common/v3/os"
	"intel/isecl/lib/common/v3/setup"
	"intel/isecl/lib/common/v3/validation"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"strconv"
	"strings"
	"syscall"
	"time"

	commLog "intel/isecl/lib/common/v3/log"
	commLogInt "intel/isecl/lib/common/v3/log/setup"
	stdlog "log"

	"github.com/pkg/errors"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
)

type App struct {
	HomeDir        string
	ConfigDir      string
	LogDir         string
	ExecutablePath string
	ExecLinkPath   string
	RunDirPath     string
	Config         *config.Configuration
	ConsoleWriter  io.Writer
	LogWriter      io.Writer
	HTTPLogWriter  io.Writer
	SecLogWriter   io.Writer
}

func (a *App) printUsage() {
	w := a.consoleWriter()

	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "    cms <command> [arguments]")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Avaliable Commands:")
	fmt.Fprintln(w, "    -h|--help            Show this help message")
	fmt.Fprintln(w, "    setup [task]         Run setup task")
	fmt.Fprintln(w, "    start                Start cms")
	fmt.Fprintln(w, "    status               Show the status of cms")
	fmt.Fprintln(w, "    stop                 Stop cms")
	fmt.Fprintln(w, "    tlscertsha384        Show the SHA384 digest of the certificate used for TLS")
	fmt.Fprintln(w, "    uninstall [--purge]  Uninstall cms. --purge option needs to be applied to remove configuration and data files")
	fmt.Fprintln(w, "    -v|--version         Show the version of cms")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Setup command usage:     cms setup [task] [--arguments=<argument_value>] [--force]")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Available Tasks for setup:")
	fmt.Fprintln(w, "    all                       Runs all setup tasks")
	fmt.Fprintln(w, "                              Required env variables:")
	fmt.Fprintln(w, "                                  - get required env variables from all the setup tasks")
	fmt.Fprintln(w, "                              Optional env variables:")
	fmt.Fprintln(w, "                                  - get optional env variables from all the setup tasks")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "    root_ca                   Creates a self signed Root CA keypair in /etc/cms/root-ca/ for quality of life")
	fmt.Fprintln(w, "                              - Option [--force] overwrites any existing files, and always generate new Root CA keypair")
	fmt.Fprintln(w, "                              Optional env variables specific to setup task are:")
	fmt.Fprintln(w, "                                  - CMS_CA_CERT_VALIDITY=<cert life span in years>     : Certificate Management Service Root Certificate Validity")
	fmt.Fprintln(w, "                                  - CMS_CA_ORGANIZATION=<cert org>                     : Certificate Management Service Root Certificate Organization")
	fmt.Fprintln(w, "                                  - CMS_CA_LOCALITY=<cert locality>                    : Certificate Management Service Root Certificate Locality")
	fmt.Fprintln(w, "                                  - CMS_CA_PROVINCE=<cert province>                    : Certificate Management Service Root Certificate Province")
	fmt.Fprintln(w, "                                  - CMS_CA_COUNTRY=<cert country>                      : Certificate Management Service Root Certificate Country")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "    intermediate_ca           Creates a root_ca signed intermediate CA keypair(signing, tls-server and tls-client) in /etc/cms/intermediate-ca/ for quality of life")
	fmt.Fprintln(w, "                              - Option [--force] overwrites any existing files, and always generate new root_ca signed Intermediate CA keypair")
	fmt.Fprintln(w, "                              Available argument specific to setup task is:")
	fmt.Fprintln(w, "                                  - type          available options are: TLS, TLS-Client, Signing")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "    tls                       Creates an intermediate_ca signed TLS keypair in /etc/cms for quality of life")
	fmt.Fprintln(w, "                              - Option [--force] overwrites any existing files, and always generate intermediate_ca signed TLS keypair")
	fmt.Fprintln(w, "                              Available argument and optional env variable specific to setup task is:")
	fmt.Fprintln(w, "                                  - host_names   alternatively, set environment variable SAN_LIST")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "    server                    Setup http server on given port")
	fmt.Fprintln(w, "                              Available arguments and optional env variables specific to task are:")
	fmt.Fprintln(w, "                                  - port         alternatively, set environment variable CMS_PORT")
	fmt.Fprintln(w, "                                  - aas-url      alternatively, set environment variable AAS_API_URL")
	fmt.Fprintln(w, "                              Optional env variables specific to setup task are:")
	fmt.Fprintln(w, "                                  - CMS_SERVER_READ_TIMEOUT=<read timeout in seconds>                    : Certificate Management Service Read Timeout")
	fmt.Fprintln(w, "                                  - CMS_SERVER_READ_HEADER_TIMEOUT=<read header timeout in seconds>      : Certificate Management Service Read Header Timeout")
	fmt.Fprintln(w, "                                  - CMS_SERVER_WRITE_TIMEOUT=<write timeout in seconds>                  : Certificate Management Service Write Timeout")
	fmt.Fprintln(w, "                                  - CMS_SERVER_IDLE_TIMEOUT=<idle timeout in seconds>                    : Certificate Management Service Idle Timeout")
	fmt.Fprintln(w, "                                  - CMS_SERVER_MAX_HEADER_BYTES=<max header bytes>            : Certificate Management Service Max Header Bytes")
	fmt.Fprintln(w, "                                  - LOG_ENTRY_MAXLENGTH=<log max length>                      : Maximum length of each entry in a log")
	fmt.Fprintln(w, "                                  - CMS_ENABLE_CONSOLE_LOG=<bool>                             : Certificate Management Service Enable standard output")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "    cms_auth_token            Create its own self signed JWT keypair in /etc/cms/jwt for quality of life")
	fmt.Fprintln(w, "                              - Option [--force] overwrites any existing files, and always generate new JWT keypair and token")
	fmt.Fprintln(w, "                              Optional env variables specific to setup task are:")
	fmt.Fprintln(w, "                                  - AAS_JWT_CN=<jwt common-name>          : Authentication and Authorization JWT Common Name")
	fmt.Fprintln(w, "                                  - AAS_TLS_CN=<tls common-name>          : Authentication and Authorization TLS Common Name")
	fmt.Fprintln(w, "                                  - AAS_TLS_SAN=<tls SAN>                 : Authentication and Authorization TLS SAN list")
	fmt.Fprintln(w, "")
}

func (a *App) consoleWriter() io.Writer {
	if a.ConsoleWriter != nil {
		return a.ConsoleWriter
	}
	return os.Stdout
}

func (a *App) logWriter() io.Writer {
	if a.LogWriter != nil {
		return a.LogWriter
	}
	return os.Stderr
}

func (a *App) httpLogWriter() io.Writer {
	if a.HTTPLogWriter != nil {
		return a.HTTPLogWriter
	}
	return os.Stderr
}

func (a *App) configuration() *config.Configuration {
	if a.Config != nil {
		return a.Config
	}
	return config.Global()
}

func (a *App) executablePath() string {
	if a.ExecutablePath != "" {
		return a.ExecutablePath
	}
	exec, err := os.Executable()
	if err != nil {
		log.WithError(err).Error("app:executablePath() Unable to find CMS executable")
		// if we can't find self-executable path, we're probably in a state that is panic() worthy
		panic(err)
	}
	return exec
}

func (a *App) homeDir() string {
	if a.HomeDir != "" {
		return a.HomeDir
	}
	return constants.HomeDir
}

func (a *App) configDir() string {
	if a.ConfigDir != "" {
		return a.ConfigDir
	}
	return constants.ConfigDir
}

func (a *App) logDir() string {
	if a.LogDir != "" {
		return a.ConfigDir
	}
	return constants.LogDir
}

func (a *App) execLinkPath() string {
	if a.ExecLinkPath != "" {
		return a.ExecLinkPath
	}
	return constants.ExecLinkPath
}

func (a *App) runDirPath() string {
	if a.RunDirPath != "" {
		return a.RunDirPath
	}
	return constants.RunDirPath
}

var log = commLog.GetDefaultLogger()
var slog = commLog.GetSecurityLogger()

var secLogFile *os.File
var defaultLogFile *os.File

func (a *App) configureLogs(isStdOut bool, isFileOut bool) {
	var ioWriterDefault io.Writer
	ioWriterDefault = a.LogWriter
	if isStdOut && isFileOut {
		ioWriterDefault = io.MultiWriter(os.Stdout, a.LogWriter)
	} else if isStdOut && !isFileOut {
		ioWriterDefault = os.Stdout
	}

	ioWriterSecurity := io.MultiWriter(ioWriterDefault, a.SecLogWriter)
	commLogInt.SetLogger(commLog.DefaultLoggerName, a.configuration().LogLevel, &commLog.LogFormatter{MaxLength: a.configuration().LogMaxLength}, ioWriterDefault, false)
	commLogInt.SetLogger(commLog.SecurityLoggerName, a.configuration().LogLevel, &commLog.LogFormatter{MaxLength: a.configuration().LogMaxLength}, ioWriterSecurity, false)

	slog.Info(message.LogInit)
	log.Info(message.LogInit)
}

func (a *App) Run(args []string) error {

	if len(args) < 2 {
		a.printUsage()
		return nil
	}
	cmd := args[1]
	switch cmd {
	default:
		a.printUsage()
		fmt.Fprintf(os.Stderr, "Unrecognized command: %s\n", args[1])
		os.Exit(1)
	case "tlscertsha384":
		a.configureLogs(a.configuration().LogEnableStdout, true)
		hash, err := crypt.GetCertHexSha384(constants.TLSCertPath)
		if err != nil {
			fmt.Println(err.Error())
			return errors.Wrap(err, "app:Run() Could not derive tls certificate digest")
		}
		fmt.Println(hash)
		return nil
	case "run":
		a.configureLogs(a.configuration().LogEnableStdout, true)
		if err := a.startServer(); err != nil {
			fmt.Fprintln(os.Stderr, "Error: daemon did not start - ", err.Error())
			// wait some time for logs to flush - otherwise, there will be no entry in syslog
			time.Sleep(10 * time.Millisecond)
			return errors.Wrap(err, "app:Run() Error starting CMS service")
		}
	case "-h", "--help":
		a.printUsage()
		return nil
	case "start":
		a.configureLogs(a.configuration().LogEnableStdout, true)
		return a.start()
	case "stop":
		a.configureLogs(a.configuration().LogEnableStdout, true)
		return a.stop()
	case "status":
		return a.status()
	case "uninstall":
		var purge bool
		flag.CommandLine.BoolVar(&purge, "purge", false, "purge config when uninstalling")
		flag.CommandLine.Parse(args[2:])
		a.uninstall(purge)
		log.Info("app:Run() Uninstalled Certificate Management Service")
		os.Exit(0)
	case "--version", "-v":
		fmt.Fprintf(a.consoleWriter(), "Certificate Management Service %s-%s\nBuilt %s\n", version.Version, version.GitHash, version.BuildDate)
		return nil
	case "setup":
		a.configureLogs(a.configuration().LogEnableStdout, true)
		if len(args) <= 2 {
			a.printUsage()
			log.Error("app:Run() Invalid command")
			os.Exit(1)
		}
		if args[2] != "tls" &&
			args[2] != "root_ca" &&
			args[2] != "intermediate_ca" &&
			args[2] != "server" &&
			args[2] != "cms_auth_token" &&
			args[2] != "all" {
			a.printUsage()
			return errors.New("No such setup task")
		}

		err := validateSetupArgs(args[2], args[3:])
		if err != nil {
			return errors.Wrap(err, "app:Run() Invalid setup task arguments")
		}

		task := strings.ToLower(args[2])
		flags := args[3:]
		setupRunner := &setup.Runner{
			Tasks: []setup.Task{
				tasks.Server{
					Flags:         flags,
					Config:        a.configuration(),
					ConsoleWriter: os.Stdout,
				},
				tasks.Root_Ca{
					Flags:         flags,
					ConsoleWriter: os.Stdout,
					Config:        a.configuration(),
				},
				tasks.Intermediate_Ca{
					Flags:         flags,
					ConsoleWriter: os.Stdout,
					Config:        a.configuration(),
				},
				tasks.TLS{
					Flags:         flags,
					ConsoleWriter: os.Stdout,
					Config:        a.configuration(),
				},
				tasks.Cms_Auth_Token{
					Flags:         flags,
					ConsoleWriter: os.Stdout,
					Config:        a.configuration(),
				},
			},
			AskInput: false,
		}
		if task == "all" {
			err = setupRunner.RunTasks()
		} else {
			err = setupRunner.RunTasks(task)
		}
		if err != nil {
			fmt.Println("Error running setup: ", err)
			return errors.Wrap(err, "app:Run() Error running setup")
		}

		//Change the fileownership to cms user
		cmsUser, err := user.Lookup(constants.CMSUserName)
		if err != nil {
			return errors.Wrapf(err, "Could not find user '%s'", constants.CMSUserName)
		}

		uid, err := strconv.Atoi(cmsUser.Uid)
		if err != nil {
			return errors.Wrapf(err, "Could not parse cms user uid '%s'", cmsUser.Uid)
		}

		gid, err := strconv.Atoi(cmsUser.Gid)
		if err != nil {
			return errors.Wrapf(err, "Could not parse cms user gid '%s'", cmsUser.Gid)
		}

		err = cos.ChownR(constants.ConfigDir, uid, gid)
		if err != nil {
			return errors.Wrap(err, "Error while changing file ownership")
		}

	}
	return nil
}

func (a *App) fnGetJwtCerts() error {
	log.Trace("app:fnGetJwtCerts() Entering")
	defer log.Trace("app:fnGetJwtCerts() Leaving")

	c := a.configuration()
	if !strings.HasSuffix(c.AuthServiceUrl, "/") {
		c.AuthServiceUrl = c.AuthServiceUrl + "/"
	}
	url := c.AuthServiceUrl + "noauth/jwt-certificates"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return errors.Wrap(err, "app:fnGetJwtCerts() Could not create http request")
	}
	req.Header.Add("accept", "application/x-pem-file")
	rootCaCertPems, err := cos.GetDirFileContents(constants.RootCADirPath, "*.pem")
	if err != nil {
		return errors.Wrap(err, "app:fnGetJwtCerts() Could not read root CA certificate")
	}

	// Get the SystemCertPool, continue with an empty pool on error
	rootCAs, _ := x509.SystemCertPool()
	if rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}
	for _, rootCACert := range rootCaCertPems {
		if ok := rootCAs.AppendCertsFromPEM(rootCACert); !ok {
			return err
		}
	}
	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: false,
				RootCAs:            rootCAs,
			},
		},
	}

	res, err := httpClient.Do(req)
	if err != nil {
		return errors.Wrap(err, "app:fnGetJwtCerts() Could not retrieve jwt certificate")
	}
	defer res.Body.Close()
	body, _ := ioutil.ReadAll(res.Body)
	err = crypt.SavePemCertWithShortSha1FileName(body, constants.TrustedJWTSigningCertsDir)
	if err != nil {
		return errors.Wrap(err, "app:fnGetJwtCerts() Could not store Certificate")
	}
	return nil
}

func (a *App) startServer() error {
	log.Trace("app:startServer() Entering")
	defer log.Trace("app:startServer() Leaving")

	c := a.configuration()

	// Create Router, set routes
	r := mux.NewRouter()

	// ISECL-8715 - Prevent potential open redirects to external URLs
	r.SkipClean(true)

	sr := r.PathPrefix("/cms/v1").Subrouter()
	func(setters ...func(*mux.Router, *config.Configuration)) {
		for _, s := range setters {
			s(sr, c)
		}
	}(resource.SetVersion, resource.SetCACertificates)

	sr = r.PathPrefix("/cms/v1/certificates").Subrouter()
	sr.Use(middleware.NewTokenAuth(constants.TrustedJWTSigningCertsDir,
		constants.ConfigDir, a.fnGetJwtCerts,
		time.Minute*constants.DefaultJwtValidateCacheKeyMins))
	func(setters ...func(*mux.Router, *config.Configuration)) {
		for _, s := range setters {
			s(sr, c)
		}
	}(resource.SetCertificates)

	tlsconfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
	}
	// Setup signal handlers to gracefully handle termination
	stop := make(chan os.Signal)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	httpLog := stdlog.New(a.httpLogWriter(), "", 0)
	h := &http.Server{
		Addr:              fmt.Sprintf(":%d", c.Port),
		Handler:           handlers.RecoveryHandler(handlers.RecoveryLogger(httpLog), handlers.PrintRecoveryStack(true))(handlers.CombinedLoggingHandler(a.httpLogWriter(), r)),
		ErrorLog:          httpLog,
		TLSConfig:         tlsconfig,
		ReadTimeout:       c.ReadTimeout,
		ReadHeaderTimeout: c.ReadHeaderTimeout,
		WriteTimeout:      c.WriteTimeout,
		IdleTimeout:       c.IdleTimeout,
		MaxHeaderBytes:    c.MaxHeaderBytes,
	}

	// dispatch web server go routine
	go func() {
		tlsCert := constants.TLSCertPath
		tlsKey := constants.TLSKeyPath
		if err := h.ListenAndServeTLS(tlsCert, tlsKey); err != nil {
			log.WithError(err).Fatal("app:startServer() Failed to start HTTPS server")
			stop <- syscall.SIGTERM
		}
	}()

	slog.Info(message.ServiceStart)
	// TODO dispatch Service status checker goroutine
	<-stop
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := h.Shutdown(ctx); err != nil {
		return errors.Wrap(err, "app:startServer() Failed to gracefully shutdown webserver")
	}
	slog.Info(message.ServiceStop)
	return nil
}

func (a *App) start() error {
	log.Trace("app:start() Entering")
	defer log.Trace("app:start() Leaving")

	fmt.Fprintln(a.consoleWriter(), `Forwarding to "systemctl start cms"`)
	systemctl, err := exec.LookPath("systemctl")
	if err != nil {
		return errors.Wrap(err, "app:start() Could not locate systemctl to start application service")
	}
	return syscall.Exec(systemctl, []string{"systemctl", "start", "cms"}, os.Environ())
}

func (a *App) stop() error {
	log.Trace("app:stop() Entering")
	defer log.Trace("app:stop() Leaving")

	fmt.Fprintln(a.consoleWriter(), `Forwarding to "systemctl stop cms"`)
	systemctl, err := exec.LookPath("systemctl")
	if err != nil {
		return errors.Wrap(err, "app:stop() Could not locate systemctl to stop application service")
	}
	return syscall.Exec(systemctl, []string{"systemctl", "stop", "cms"}, os.Environ())
}

func (a *App) status() error {
	log.Trace("app:status() Entering")
	defer log.Trace("app:status() Leaving")

	fmt.Fprintln(a.consoleWriter(), `Forwarding to "systemctl status cms"`)
	systemctl, err := exec.LookPath("systemctl")
	if err != nil {
		return errors.Wrap(err, "app:status() Could not locate systemctl to check status of application service")
	}
	return syscall.Exec(systemctl, []string{"systemctl", "status", "cms"}, os.Environ())
}

func (a *App) uninstall(purge bool) {
	log.Trace("app:uninstall() Entering")
	defer log.Trace("app:uninstall() Leaving")

	fmt.Println("Uninstalling Certificate Management Service")
	removeService()

	fmt.Println("removing : ", a.executablePath())
	err := os.Remove(a.executablePath())
	if err != nil {
		log.WithError(err).Error("error removing executable")
	}

	fmt.Println("removing : ", a.runDirPath())
	err = os.Remove(a.runDirPath())
	if err != nil {
		log.WithError(err).Error("error removing ", a.runDirPath())
	}
	fmt.Println("removing : ", a.execLinkPath())
	err = os.Remove(a.execLinkPath())
	if err != nil {
		log.WithError(err).Error("error removing ", a.execLinkPath())
	}

	if purge {
		fmt.Println("removing : ", a.configDir())
		err = os.RemoveAll(a.configDir())
		if err != nil {
			log.WithError(err).Error("error removing config dir")
		}
	}
	fmt.Println("removing : ", a.logDir())
	err = os.RemoveAll(a.logDir())
	if err != nil {
		log.WithError(err).Error("error removing log dir")
	}
	fmt.Println("removing : ", a.homeDir())
	err = os.RemoveAll(a.homeDir())
	if err != nil {
		log.WithError(err).Error("error removing home dir")
	}
	fmt.Fprintln(a.consoleWriter(), "Certificate Management Service uninstalled")
	a.stop()
}
func removeService() {
	log.Trace("app:removeService() Entering")
	defer log.Trace("app:removeService() Leaving")

	_, _, err := e.RunCommandWithTimeout(constants.ServiceRemoveCmd, 5)
	if err != nil {
		fmt.Println("Could not remove Certificate Management Service")
		fmt.Println("Error : ", err)
	}
}

func validateCmdAndEnv(env_names_cmd_opts map[string]string, flags *flag.FlagSet) error {
	log.Trace("app:validateCmdAndEnv() Entering")
	defer log.Trace("app:validateCmdAndEnv() Leaving")

	env_names := make([]string, 0)
	for k, _ := range env_names_cmd_opts {
		env_names = append(env_names, k)
	}

	missing, err := validation.ValidateEnvList(env_names)
	if err != nil && missing != nil {
		for _, m := range missing {
			if cmd_f := flags.Lookup(env_names_cmd_opts[m]); cmd_f == nil {
				return errors.Wrap(err, "app:validateCmdAndEnv() Insufficient arguments")
			}
		}
	}
	return nil
}

func validateSetupArgs(cmd string, args []string) error {
	log.Trace("app:validateSetupArgs() Entering")
	defer log.Trace("app:validateSetupArgs() Leaving")

	var fs *flag.FlagSet

	switch cmd {
	default:
		return errors.New("Unknown command")

	case "server":
		return nil

	case "root_ca":
		return nil

	case "intermediate_ca":
		return nil

	case "tls":

		env_names_cmd_opts := map[string]string{
			"SAN_LIST": "host_names",
		}

		fs = flag.NewFlagSet("tls", flag.ContinueOnError)
		fs.String("host_names", "", "comma separated list of hostnames to add to TLS cert")
		fs.Bool("force", false, "force run of setup task")

		err := fs.Parse(args)
		if err != nil {
			return errors.Wrap(err, "app:validateCmdAndEnv() Fail to parse arguments")
		}
		return validateCmdAndEnv(env_names_cmd_opts, fs)

	case "cms_auth_token":
		return nil

	case "all":
		if len(args) != 0 {
			return errors.New("app:validateCmdAndEnv() Please setup the arguments with env")
		}
	}

	return nil
}
