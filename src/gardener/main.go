package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"
	"syscall"

	"code.cloudfoundry.org/bbs"
	"code.cloudfoundry.org/bbs/models"
	"code.cloudfoundry.org/lager"

	"github.com/cloudfoundry-community/go-cfclient"

	loggregator "code.cloudfoundry.org/go-loggregator"
)

type FalcoEvent struct {
	Output       string `json:"output"`
	Priority     string `json:"priority"`
	Rule         string `json:"rule"`
	Time         string `json:"time"`
	OutputFields struct {
		PID   int `json:"proc.pid"`
		PPID  int `json:"proc.ppid"`
		PPPID int `json:"proc.apid"`
	} `json:"output_fields"`
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

func getAppInfoFromContainerID(containerID string, client bbs.Client) (string, int, error) {
	// sigh... why does the bbs client demand you give it a logger?
	logger := lager.NewLogger("gardener")

	// since we have to iterate over all ActualLRPs to find the one we want
	// make it a bit faster by filtering by the our instance id
	// since we know the event happened on the cell we are running on
	cellID, err := ioutil.ReadFile("/var/vcap/instance/id")
	if err != nil {
		return "", -1, err
	}
	actualLRPFilter := models.ActualLRPFilter{
		CellID: string(cellID),
		Domain: "",
	}

	actualLRPGroups, err := client.ActualLRPGroups(logger, actualLRPFilter)
	if err != nil {
		return "", -1, err
	}

	// iterate through each ActualLRP group to find the one that matches our instance id
	// then find the DesiredLRP that created our instance
	// With those two pieces of info, we can find our App ID to send logs to
	// and the actual index of the app that raised the alert
	for _, actualLRPGroup := range actualLRPGroups {
		if actualLRPGroup.Instance.ActualLRPInstanceKey.InstanceGuid == containerID {

			desiredLRP, err := client.DesiredLRPByProcessGuid(logger, actualLRPGroup.Instance.ActualLRPKey.ProcessGuid)
			if err != nil {
				return "", -1, err
			}

			return desiredLRP.LogGuid, int(actualLRPGroup.Instance.ActualLRPKey.Index), nil
		}
	}

	return "", -1, fmt.Errorf("Unable to find app for container id %s", containerID)
}

func parseDadooCmd(cmdline []string) (bool, string) {
	if !strings.HasSuffix(cmdline[0], "dadoo") {
		return false, ""
	}

	fs := flag.NewFlagSet("cmd", flag.ContinueOnError)

	fs.Bool("tty", false, "")
	fs.String("socket-dir-path", "", "")

	fs.Parse(cmdline[1:])

	args := fs.Args()

	if len(args) < 4 || args[0] != "exec" {
		return false, ""
	}

	return true, args[3]
}

func main() {
	exitCode := 0
	defer func() {
		os.Exit(exitCode)
	}()

	stat, _ := os.Stdin.Stat()
	if (stat.Mode() & os.ModeCharDevice) != 0 {
		fmt.Println("This program expects to receive JSON on stdin.")
		fmt.Println("It was designed to be called by Falco via program_output with json_output: true")
		fmt.Println("https://github.com/draios/falco/wiki/Falco-Configuration")
		exitCode = 1
		return
	}

	// connect to BBS
	bbsClient, err := bbs.NewSecureClient(
		"https://bbs.service.cf.internal:8889",
		os.Getenv("BBS_CA_CERT_PATH"),
		os.Getenv("BBS_CERT_PATH"),
		os.Getenv("BBS_KEY_PATH"),
		0,
		0,
	)
	if err != nil {
		fmt.Printf("Could not create CF client: %v\n", err)
		exitCode = 2
		return
	}

	tlsConfig, err := loggregator.NewIngressTLSConfig(
		os.Getenv("LOGGREGATOR_CA_CERT_PATH"),
		os.Getenv("METRON_CERT_PATH"),
		os.Getenv("METRON_KEY_PATH"),
	)
	if err != nil {
		fmt.Printf("Could not create TLS config: %v\n", err)
		exitCode = 3
		return
	}
	logClient, err := loggregator.NewIngressClient(
		tlsConfig,
		loggregator.WithAddr("localhost:3458"),
	)
	if err != nil {
		fmt.Printf("Could not create v2 client: %v\n", err)
		exitCode = 3
		return
	}

	cfClient, err := cfclient.NewClient(&cfclient.Config{
		ApiAddress:   os.Getenv("API_ADDRESS"),
		ClientID:     os.Getenv("CLIENT_ID"),
		ClientSecret: os.Getenv("CLIENT_SECRET"),
	})
	if err != nil {
		fmt.Printf("Could not create CF client: %v\n", err)
		exitCode = 4
		return
	}

	// make sure we emit any queue log events before exiting
	defer logClient.CloseSend()

	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		if err := handleEvent(scanner.Text(), bbsClient, logClient, cfClient); err != nil {
			fmt.Printf("Error processing event: %s\n", err)
			exitCode = 5
			return
		}
	}
	if err := scanner.Err(); err != nil {
		fmt.Printf("Error reading standard input: %s\n", err)
		exitCode = 6
		return
	}
}

func getEventPID(evt FalcoEvent) (int, error) {
	pids := []int{evt.OutputFields.PID, evt.OutputFields.PPID, evt.OutputFields.PPPID}
	var err error
	for _, pid := range pids {
		err = checkPid(pid)
		if err == nil {
			return pid, nil
		}
	}
	return 0, err
}

func handleEvent(data string, bbsClient bbs.Client, logClient *loggregator.IngressClient, cfClient *cfclient.Client) error {
	evt := FalcoEvent{}
	if err := json.Unmarshal([]byte(data), &evt); err != nil {
		return err
	}

	// if our pid doesn't exist, try the parent.  if it doesn't exist bail
	opid, err := getEventPID(evt)
	if err != nil {
		fmt.Printf("%v\n", err)
		return nil
	}

	// walk up the process tree to find the guardian parent process
	var pid int = opid
	var isDadooCmd bool
	var containerID string
	for {
		if pid == 1 {
			fmt.Printf("Process %v is not running in a garden container\n", opid)
			return nil
		}

		// ASSUMPTION 1: The process we are expecting to find will be named "dadoo", and the third arg to exec subcommand is the container id
		// https://github.com/cloudfoundry/guardian/blob/d7d2e66b12955edc8b4f8e452ad85480de37d834/cmd/dadoo/main_linux.go#L43
		cmdline := getCmdline(pid)
		isDadooCmd, containerID = parseDadooCmd(cmdline)
		if isDadooCmd {
			break
		}

		pid = getParent(pid)
	}

	// ASSUMPTION 2: The app id is the log_guid attached to the destired-lrp in the BBS
	appID, appIndex, err := getAppInfoFromContainerID(containerID, bbsClient)
	if err != nil {
		fmt.Printf("Could not lookup container %v: %v\n", containerID, err)
		return nil
	}

	fmt.Printf("Container %v has CF app id %v\n", containerID, appID)

	logClient.EmitLog(
		evt.Output,
		loggregator.WithAppInfo(appID, "FALCO", strconv.Itoa(appIndex)),
	)

	// TODO: Make this not a toy, but have real logic for what types of events trigger actions in CF
	if evt.Priority == "Alert" {
		err = cfClient.KillAppInstance(appID, strconv.Itoa(appIndex))
		if err != nil {
			fmt.Printf("Could not kill app instance: %v\n", err)
			return err
		}
	}

	return nil
}
