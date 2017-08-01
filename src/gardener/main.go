package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	gclient "code.cloudfoundry.org/garden/client"
	gconn "code.cloudfoundry.org/garden/client/connection"
	loggregator "code.cloudfoundry.org/go-loggregator"
)

const FalcoSplit = "♥"

type FalcoEvent struct {
	Output   string `json:"output"`
	Priority string `json:"priority"`
	Rule     string `json:"rule"`
	Time     string `json:"time"`
	Pid      int
	PPid     int
	Message  string
}

func getParent(pid int) int {

	stat, err := ioutil.ReadFile(path.Join("/proc", strconv.Itoa(pid), "stat"))
	if err != nil {
		panic(err)
	}

	r, err := regexp.Compile(`^\d+ \(.*\) . (\d+)`)
	if err != nil {
		panic(err)
	}

	ppid, err := strconv.Atoi(string(r.FindSubmatch(stat)[1]))
	if err != nil {
		panic(err)
	}

	return ppid
}

func getCmdline(pid int) []string {
	b, err := ioutil.ReadFile(path.Join("/proc", strconv.Itoa(pid), "cmdline"))
	if err != nil {
		panic(err)
	}

	cmdline := []string{}

	for _, arg := range bytes.Split(b, make([]byte, 1)) {
		if len(arg) > 0 {
			cmdline = append(cmdline, string(arg))
		}
	}

	return cmdline
}

func checkPid(pid int) error {
	// make sure the pid is valid
	target_process, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("Error finding process %v: %v\n", pid, err)
	}
	err = target_process.Signal(syscall.Signal(0))
	if err != nil && err != syscall.EPERM {
		return fmt.Errorf("Process %v does not exist: %v\n", pid, err)
	}

	return nil
}

func main() {
	stat, _ := os.Stdin.Stat()
	if (stat.Mode() & os.ModeCharDevice) != 0 {
		fmt.Println("This program expects to receive JSON on stdin.")
		fmt.Println("It was designed to be called by Falco via program_output with json_output: true")
		fmt.Println("https://github.com/draios/falco/wiki/Falco-Configuration")
		os.Exit(1)
	}

	evt := FalcoEvent{}
	stdin, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		fmt.Printf("Failure reading stdin %v\n", err)
		os.Exit(2)
	}

	if err := json.Unmarshal(stdin, &evt); err != nil {
		fmt.Printf("Failure parsing JSON: %v\n", err)
		os.Exit(2)
	}

	// this mess to get the pid out of our output
	// TODO: PR to fix this and get better output: https://github.com/draios/falco/issues/261
	hax := strings.Split(evt.Output, FalcoSplit)

	evt.Message = hax[0]

	opid, err := strconv.Atoi(strings.TrimSpace(hax[1]))
	if err != nil {
		fmt.Printf("%v is not a valid pid. It must be an integer.\n", hax[1])
		os.Exit(3)
	}
	evt.Pid = opid
	ppid, err := strconv.Atoi(strings.TrimSpace(hax[2]))
	if err != nil {
		fmt.Printf("%v is not a valid pid. It must be an integer.\n", hax[2])
		os.Exit(3)
	}
	evt.PPid = ppid

	// if our pid doesn't exist, try the parent.  if it doesn't exist bail
	if checkPid(opid) != nil {
		opid = evt.PPid

		if err := checkPid(opid); err != nil {
			fmt.Printf("%v", err)
			os.Exit(4)
		}
	}

	// walk up the process tree to find the guardian parent process
	var pid int = opid
	var containerId string
	for {
		if pid == 1 {
			fmt.Printf("Process %v is not running in a garden container\n", opid)
			os.Exit(5)
		}

		// ASSUMPTION 1: The process we are expecting to find will be named "dadoo", and the third arg to exec subcommand is the container id
		// https://github.com/cloudfoundry/guardian/blob/d7d2e66b12955edc8b4f8e452ad85480de37d834/cmd/dadoo/main_linux.go#L43
		cmdline := getCmdline(pid)
		if strings.HasSuffix(cmdline[0], "dadoo") && cmdline[2] == "exec" {
			containerId = cmdline[5]
			break
		}

		pid = getParent(pid)
	}

	// ASSUMPTION 2: The container will have a property network.app_id
	// https://github.com/cloudfoundry/cloud_controller_ng/blob/4e850d050bb7af09f279b56ba6c66af63fe2d35c/spec/unit/lib/cloud_controller/diego/app_recipe_builder_spec.rb#L66
	container, err := gclient.New(gconn.New("tcp", "127.0.0.1:7777")).Lookup(containerId)
	if err != nil {
		fmt.Printf("Could not lookup container %v: %v\n", containerId, err)
		os.Exit(6)
	}
	properties, err := container.Properties()
	if err != nil {
		fmt.Printf("Could not get properties for container %v: %v\n", containerId, err)
		os.Exit(6)
	}

	fmt.Printf("Container %v has CF app id %v\n", containerId, properties["network.app_id"])

	tlsConfig, err := loggregator.NewIngressTLSConfig(
		os.Getenv("CA_CERT_PATH"),
		os.Getenv("CERT_PATH"),
		os.Getenv("KEY_PATH"),
	)
	if err != nil {
		fmt.Printf("Could not create TLS config: %v\n", err)
		os.Exit(7)
	}
	v2Client, err := loggregator.NewIngressClient(
		tlsConfig,
		loggregator.WithAddr("localhost:3458"),
	)
	if err != nil {
		fmt.Printf("Could not create v2 client: %v\n", err)
		os.Exit(7)
	}

	v2Client.EmitLog(
		evt.Message,
		loggregator.WithAppInfo(properties["network.app_id"], "FALCO", "0"),
	)
	time.Sleep(time.Second * 2) // https://github.com/cloudfoundry-incubator/go-loggregator/issues/18
}
