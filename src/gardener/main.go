package main

import (
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
	"time"

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
		PID  int `json:"proc.pid"`
		PPID int `json:"proc.ppid"`
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

func getAppInfoFromContainerID(containerID string) (string, int, error) {
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
	cellID, err := ioutil.ReadFile("/var/vcap/instance/id")
	if err != nil {
		return "", -1, err
	}
	actualLRPFilter := models.ActualLRPFilter{
		CellID: string(cellID),
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
		if actualLRPGroup.Instance.ActualLRPInstanceKey.InstanceGuid == containerID {

			desiredLRP, err := bbsClient.DesiredLRPByProcessGuid(logger, actualLRPGroup.Instance.ActualLRPKey.ProcessGuid)
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

	// if our pid doesn't exist, try the parent.  if it doesn't exist bail
	opid := evt.OutputFields.PID

	if checkPid(opid) != nil {
		opid = evt.OutputFields.PPID

		if err := checkPid(opid); err != nil {
			fmt.Printf("%v", err)
			os.Exit(4)
		}
	}

	// walk up the process tree to find the guardian parent process
	var pid int = opid
	var isDadooCmd bool
	var containerID string
	for {
		if pid == 1 {
			fmt.Printf("Process %v is not running in a garden container\n", opid)
			os.Exit(5)
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
	appID, appIndex, err := getAppInfoFromContainerID(containerID)
	if err != nil {
		fmt.Printf("Could not lookup container %v: %v\n", containerID, err)
		os.Exit(6)
	}

	fmt.Printf("Container %v has CF app id %v\n", containerID, appID)

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
		evt.Output,
		loggregator.WithAppInfo(appID, "FALCO", strconv.Itoa(appIndex)),
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

		err = cfClient.KillAppInstance(appID, strconv.Itoa(appIndex))
		if err != nil {
			fmt.Printf("Could not kill app instance: %v\n", err)
			os.Exit(9)
		}
	}
}
