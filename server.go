// +build linux

package main

import (
	"intel/isecl/cms/resource"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"io/ioutil"
	//"syscall"
	"strconv"
	"context"
	"time"

	log "github.com/sirupsen/logrus"
	stdlog "log"
	"github.com/gorilla/mux"
	"github.com/gorilla/handlers"
)


func startServer() {
	
	r := mux.NewRouter().PathPrefix("/v2/cms").Subrouter()
	// Set Resource Endpoints
	resource.SetCACertificatesEndpoints(r.PathPrefix("/ca-certificates").Subrouter())
	resource.SetCertificatesEndpoints(r.PathPrefix("/certificates").Subrouter())

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)

	httpWriter := os.Stderr
	if httpLogFile, err := os.OpenFile("/var/log/cms/http.log", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0666); err != nil {
		log.WithError(err).Info("Failed to open http log file")
	} else {
		defer httpLogFile.Close()
		httpWriter = httpLogFile
	}
	l := stdlog.New(httpWriter, "", 0)
	h := &http.Server{
		Addr:     fmt.Sprintf(":%d", 9000),
		Handler:  handlers.RecoveryHandler(handlers.RecoveryLogger(l), handlers.PrintRecoveryStack(true))(handlers.CombinedLoggingHandler(httpWriter, r)),
		ErrorLog: l,
	}
	// dispatch http listener on separate go routine
	fmt.Println("Starting Certificate Management Service ...")
	go func() {
		fmt.Println("Certificate Management Service Started")
		if err := h.ListenAndServe(); err != nil {
			log.Fatal(err)
		}
	}()
	// wait for a signal on the stop channel
	<-stop // swallow the value, as we don't really care what it is

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := h.Shutdown(ctx); err != nil {
		fmt.Printf("Failed to gracefully shutdown CMS server: %v\n", err)
	} else {
		fmt.Println("Certificate Management Service stopped")
	}
}

func stopServer() {
	pid, err := readPid()
	if err != nil {
		log.WithError(err).Error("Failed to stop server")
	}
	if err := syscall.Kill(pid, syscall.SIGQUIT); err != nil {
		log.WithError(err).Error("Failed to kill server")
	}
	fmt.Println("Workload Service Stopped")
}

func readPid() (int, error) {
	pidData, err := ioutil.ReadFile("/var/run/cms/cms.pid")
	if err != nil {
		log.WithError(err).Debug("Failed to read pidfile")
		return 0, err
	}
	pid, err := strconv.Atoi(string(pidData))
	if err != nil {
		log.WithError(err).WithField("pid", pidData).Debug("Failed to convert pidData string to int")
		return 0, err
	}
	return pid, nil
}