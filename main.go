// +build linux

package main

import (
	"fmt"
	"os"
	"strings"
	"syscall"
	//"strconv"
	//csetup "intel/isecl/lib/common/setup"
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
	/*case "setup":
	//TODO: Check if CMS_NOSETUP parameter needs to be set
	if nosetup, err := strconv.ParseBool(os.Getenv("CMS_NOSETUP")); err != nil && nosetup == false {
		setupRunner := &csetup.Runner{
			Tasks: []csetup.Task{
				new(),
			},
			AskInput: false,
		}
		err := setupRunner.RunTasks(args[1:]...)
		if err != nil {
			fmt.Println("Error running setup: ", err)
			os.Exit(1)
		}
		} else {
			fmt.Println("WLS_NOSETUP is set, skipping setup")
			os.Exit(1)
		}
	}*/
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
	fmt.Println("Not yet supported")
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
	//fmt.Printf("\t\t\t-Supported tasks - server database\n")
	fmt.Printf("\tExample :-\n")
	fmt.Printf("\t\t%s setup\n", os.Args[0])
	//fmt.Printf("\t\t%s setup database\n", os.Args[0])
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
