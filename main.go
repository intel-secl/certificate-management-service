// +build linux

package main

import (
	"os"
	"fmt"
	"strings"
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
		}*/
	case "status":
		if s := status(); s == Running {
			fmt.Println("Workload Service is running")
		} else {
			fmt.Println("Workload Service is stopped")
		}
	case "start":
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
	fmt.Printf("\tsetup\n\n")
	fmt.Printf("setup command is used to run setup tasks\n")
	fmt.Printf("\tusage : %s setup [<tasklist>]\n", os.Args[0])
	fmt.Printf("\t\t<tasklist>-space seperated list of tasks\n")
	//fmt.Printf("\t\t\t-Supported tasks - server database\n")
	fmt.Printf("\tExample :-\n")
	fmt.Printf("\t\t%s setup\n", os.Args[0])
	//fmt.Printf("\t\t%s setup database\n", os.Args[0])
	fmt.Printf("\tstatus\n\n")
	fmt.Printf("status command is used to check the status of cms service\n")
	fmt.Printf("\tusage : %s status\n", os.Args[0])
	fmt.Printf("\tstart\n\n")
	fmt.Printf("start command is used to start the cms server\n")
	fmt.Printf("\tusage : %s start\n", os.Args[0])
	fmt.Printf("\tstop\n\n")
	fmt.Printf("stop command is used to stop the cms server\n")
	fmt.Printf("\tusage : %s start\n", os.Args[0])
	fmt.Printf("\tuninstall\n\n")
	fmt.Printf("uninstall command is used to uninstall the cms\n")
	fmt.Printf("\tusage : %s start\n", os.Args[0])
}
