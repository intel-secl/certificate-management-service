// +build linux

package main

import (
	"fmt"
	"intel/isecl/cms/setup"
	csetup "intel/isecl/lib/common/setup"
	"os"
	"strconv"
	"strings"
	"syscall"
)

func main() {
	/* PARSE COMMAND LINE OPTIONS */
	args := os.Args[1:]
	if len(args) <= 0 {
		fmt.Println("Command not found. Usage below ", os.Args[0])
		printUsage()
		return
	}
	switch arg := strings.ToLower(args[0]); arg {
	case "setup":
		if nosetup, err := strconv.ParseBool(os.Getenv("CMS_NOSETUP")); err == nil && nosetup == false {
			installRunner := &csetup.Runner{
				Tasks: []csetup.Task{
					setup.Configurer{},
				},
				AskInput: false,
			}
			err := installRunner.RunTasks("Configurer")
			if err != nil {
				fmt.Println("Error running setup: ", err)
				os.Exit(1)
			}

			setupRunner := &csetup.Runner{
				Tasks: []csetup.Task{
					new(setup.CreateRootCACertificate),
					new(setup.CreateTLSCertificate),
				},
				AskInput: false,
			}
			err = setupRunner.RunTasks(args[1:]...)
			if err != nil {
				fmt.Println("Error running setup: ", err)
				os.Exit(1)
			}
		} else {
			fmt.Println("CMS_NOSETUP is set, skipping setup")
			os.Exit(1)
		}
	case "status":
		if s := status(); s == Running {
			fmt.Println("Certificate Management Service is running")
		} else {
			fmt.Println("Certificate Management Service is stopped")
		}
	case "start":
		start()
	case "startserver":
		// this runs in attached mode
		startServer()
	case "stop":
		stopServer()
	case "uninstall":
		uninstall()
	default:
		fmt.Printf("Unrecognized option : %s\n", arg)
		fallthrough
	case "help", "-help", "--help":
		printUsage()
	}
}

const pidPath = "/var/run/cms/cms.pid"

// Status indicate the process status of WLS
type Status bool

const (
	Stopped Status = false
	Running Status = true
)

func status() Status {
	pid, err := readPid()
	if err != nil {
		os.Remove(pidPath)
		return Stopped
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		return Stopped
	}
	if err := p.Signal(syscall.Signal(0)); err != nil {
		return Stopped
	}
	return Running
}

func uninstall() {
	fmt.Println("Uninstalling Certificate Management Service....")
	stopServer()
	os.RemoveAll("/opt/cms")
	os.Remove("/usr/local/bin/cms")
	os.RemoveAll("/etc/cms")
	os.RemoveAll("/var/run/cms")
	os.RemoveAll("/var/lib/cms")
	os.RemoveAll("/var/log/cms")
	fmt.Println("Certificate Management Service uninstalled")
}

func printUsage() {
	fmt.Printf("Certificate Management Service\n")
	fmt.Printf("===============\n\n")
	fmt.Printf("usage : %s <command> [<args>]\n\n", os.Args[0])
	fmt.Printf("Following are the list of commands\n")
	fmt.Printf("setup:")
	fmt.Printf("setup command is used to run setup tasks\n")
	fmt.Printf("\tusage : %s setup [<tasklist>]\n", os.Args[0])
	fmt.Printf("\t\t<tasklist>-space seperated list of tasks\n")
	fmt.Printf("\t\t\t-Supported tasks - create-root-ca-certificate  create-tls-certificate \n")
	fmt.Printf("\tExample :- setup create-root-ca-certificate\n")
	fmt.Printf("status:\n")
	fmt.Printf("\tstatus command is used to check the status of cms service\n")
	fmt.Printf("\tusage : %s status\n", os.Args[0])
	fmt.Printf("start:\n")
	fmt.Printf("\tstart command is used to start the cms server\n")
	fmt.Printf("\tusage : %s start\n", os.Args[0])
	fmt.Printf("stop:\n")
	fmt.Printf("\tstop command is used to stop the cms server\n")
	fmt.Printf("\tusage : %s stop\n", os.Args[0])
	fmt.Printf("uninstall:\n")
	fmt.Printf("\tuninstall command is used to uninstall the cms\n")
	fmt.Printf("\tusage : %s uninstall\n", os.Args[0])
}
