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

	"code.cloudfoundry.org/bbs"
	"code.cloudfoundry.org/bbs/models"
	"code.cloudfoundry.org/lager"

	"github.com/cloudfoundry-community/go-cfclient"

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

func getAppInfoFromContainerId(containerId string) (string, int, error) {
	// sigh... why does the bbs client demand you give it a logger?
	logger := lager.NewLogger("gardener")

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
		return "", -1, err
	}

	// since we have to iterate over all ActualLRPs to find the one we want
	// make it a bit faster by filtering by the our instance id
	// since we know the event happened on the cell we are running on
	cellId, err := ioutil.ReadFile("/var/vcap/instance/id")
	if err != nil {
		return "", -1, err
	}
	actualLRPFilter := models.ActualLRPFilter{
		CellID: string(cellId),
		Domain: "",
	}

	actualLRPGroups, err := bbsClient.ActualLRPGroups(logger, actualLRPFilter)
	if err != nil {
		return "", -1, err
	}

	// iterate through each ActualLRP group to find the one that matches our instance id
	// then find the DesiredLRP that created our instance
	// With those two pieces of info, we can find our App ID to send logs to
	// and the actual index of the app that raised the alert
	for _, actualLRPGroup := range actualLRPGroups {
		if actualLRPGroup.Instance.ActualLRPInstanceKey.InstanceGuid == containerId {

			desiredLRP, err := bbsClient.DesiredLRPByProcessGuid(logger, actualLRPGroup.Instance.ActualLRPKey.ProcessGuid)
			if err != nil {
				return "", -1, err
			}

			return desiredLRP.LogGuid, int(actualLRPGroup.Instance.ActualLRPKey.Index), nil
		}
	}

	return "", -1, fmt.Errorf("Unable to find app for container id %s", containerId)
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

	// this mess is to get the pid out of our output
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

	// ASSUMPTION 2: The app id is the log_guid attached to the destired-lrp in the BBS
	appId, appIndex, err := getAppInfoFromContainerId(containerId)
	if err != nil {
		fmt.Printf("Could not lookup container %v: %v\n", containerId, err)
		os.Exit(6)
	}

	fmt.Printf("Container %v has CF app id %v\n", containerId, appId)

	tlsConfig, err := loggregator.NewIngressTLSConfig(
		os.Getenv("LOGGREGATOR_CA_CERT_PATH"),
		os.Getenv("METRON_CERT_PATH"),
		os.Getenv("METRON_KEY_PATH"),
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
		loggregator.WithAppInfo(appId, "FALCO", strconv.Itoa(appIndex)),
	)
	time.Sleep(time.Second * 2) // https://github.com/cloudfoundry-incubator/go-loggregator/issues/18

	// TODO: Make this not a toy, but have real logic for what types of events trigger actions in CF
	if evt.Priority == "Alert" {

		cfClient, err := cfclient.NewClient(&cfclient.Config{
			ApiAddress:   os.Getenv("API_ADDRESS"),
			ClientID:     os.Getenv("CLIENT_ID"),
			ClientSecret: os.Getenv("CLIENT_SECRET"),
		})

		if err != nil {
			fmt.Printf("Could not create CF client: %v\n", err)
			os.Exit(8)
		}

		err = cfClient.KillAppInstance(appId, strconv.Itoa(appIndex))
		if err != nil {
			fmt.Printf("Could not kill app instance: %v\n", err)
			os.Exit(9)
		}
	}
}
