// Copyright 2020 the Drone Authors. All rights reserved.
// Use of this source code is governed by the Blue Oak Model License
// that can be found in the LICENSE file.

package plugin

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/drone/drone-go/drone"
)

const dockerExe = "/usr/local/bin/docker"
const dockerdExe = "/usr/local/bin/dockerd"
const dockerHome = "/root/.docker/"
const bashExe = "/bin/sh"

type (
	// Login defines Docker  parameters.
	Login struct {
		Registry string `envconfig:"PLUGIN_REGISTRY" default:"https://index.docker.io/v1/"` // Docker registry address
		Username string `envconfig:"PLUGIN_USERNAME"`                                       // Docker registry username
		Password string `envconfig:"PLUGIN_PASSWORD"`                                       // Docker registry password
		Email    string `envconfig:"PLUGIN_EMAIL"`                                          // Docker registry email
		Config   string `envconfig:"PLUGIN_CONFIG"`                                         // Docker Auth Config
	}

	Daemon struct {
		PluginRegistry string   `envconfig:"PLUGIN_REGISTRY" default:"https://index.docker.io/v1/"` // Docker registry
		Mirror         string   `envconfig:"PLUGIN_MIRROR"`                                         // Docker registry mirror
		Insecure       bool     `envconfig:"PLUGIN_INSECURE"`                                       // Docker daemon enable insecure registries
		StorageDriver  string   `envconfig:"PLUGIN_STORAGE_DRIVER"`                                 // Docker daemon storage driver
		StoragePath    string   `envconfig:"PLUGIN_STORAGE_PATH" default:"/var/lib/docker"`         // Docker daemon storage path
		Disabled       bool     `envconfig:"PLUGIN_DAEMON_OFF"`                                     // Docker daemon is disabled (already running)
		Debug          bool     `envconfig:"PLUGIN_DEBUG"`                                          // Docker daemon started in debug mode
		Bip            string   `envconfig:"PLUGIN_BIP"`                                            // Docker daemon network bridge IP address
		DNS            []string `envconfig:"PLUGIN_CUSTOM_DNS"`                                     // Docker daemon dns server
		DNSSearch      []string `envconfig:"PLUGIN_CUSTOM_DNS_SEARCH"`                              // Docker daemon dns search domain
		MTU            string   `envconfig:"PLUGIN_MTU"`                                            // Docker daemon mtu setting
		IPv6           bool     `envconfig:"PLUGIN_IPV6"`                                           // Docker daemon IPv6 networking
		Experimental   bool     `envconfig:"PLUGIN_EXPERIMENTAL"`                                   // Docker daemon enable experimental mode
	}

	ScanDocker struct {
		BaseImage            string `json:"baseImage"`
		BaseImageRemediation struct {
			Code   string `json:"code"`
			Advice []struct {
				Message string `json:"message"`
				Bold    bool   `json:"bold,omitempty"`
			} `json:"advice"`
		} `json:"baseImageRemediation"`
	}

	ScanResults struct {
		Vulnerabilities []struct {
			PackageName          string `json:"packageName"`
			Severity             string `json:"severity"`
			SeverityWithCritical string `json:"severityWithCritical"`
		} `json:"vulnerabilities"`
		Ok              bool       `json:"ok"`
		DependencyCount int        `json:"dependencyCount"`
		Docker          ScanDocker `json:"docker"`
		Summary         string     `json:"summary"`
		UniqueCount     int        `json:"uniqueCount"`
		ProjectName     string     `json:"projectName"`
		Platform        string     `json:"platform"`
		Path            string     `json:"path"`
		Target          struct {
			Image string `json:"image"`
		} `json:"target"`
		Data struct {
			OrgOpencontainersImageCreated  time.Time `json:"org.opencontainers.image.created"`
			OrgOpencontainersImageRevision string    `json:"org.opencontainers.image.revision"`
		} `json:"data,omitempty"`
	}

	ScanSummary struct {
		Issues struct {
			Critical int64 `json:"critical"`
			High     int64 `json:"high"`
			Medium   int64 `json:"medium"`
			Low      int64 `json:"low"`
		}
		Docker      ScanDocker `json:"docker"`
		Summary     string     `json:"summary"`
		UniqueCount int        `json:"uniqueCount"`
		ProjectName string     `json:"projectName"`
		Platform    string     `json:"platform"`
		Path        string     `json:"path"`
	}
)

const Esc = "\u001B"

var (
	prefix = Esc + "]1338;"
	suffix = Esc + "]0m"
)

// Args provides plugin execution arguments.
type Args struct {
	Pipeline
	Login             Login
	Daemon            Daemon
	Level             string `envconfig:"PLUGIN_LOG_LEVEL"`
	Dockerfile        string `envconfig:"PLUGIN_DOCKERFILE"`
	Image             string `envconfig:"PLUGIN_IMAGE" required:"true"`
	SnykToken         string `envconfig:"PLUGIN_SNYK_TOKEN"`
	SeverityThreshold string `envconfig:"PLUGIN_SEVERITY_THRESHOLD"`
	FailOnIssues      bool   `envconfig:"PLUGIN_FAIL_ON_ISSUES"`
	CardFilePath      string `envconfig:"DRONE_CARD_PATH"`
}

// Exec executes the plugin.
func Exec(ctx context.Context, args Args) error {
	if !args.Daemon.Disabled {
		startDaemon(args.Daemon)
	}

	fmt.Printf("Current Unix Time: %v\n", time.Now().Unix())

	var results ScanResults
	severityLevel := strings.ToLower(args.SeverityThreshold)
	switch severityLevel {
	case "critical",
		"high",
		"medium",
		"low":
		fmt.Printf("Severity Threshold level set at %s\n", severityLevel)
	case "":
		fmt.Printf("Severity Threshold level not set.")
	default:
		return fmt.Errorf("invalid severity level input, must be critical, high, medium or low")
	}

	// poll the docker daemon until it is started. This ensures the daemon is
	// ready to accept connections before we proceed.
	for i := 0; ; i++ {
		cmd := commandInfo()
		err := cmd.Run()
		if err == nil {
			break
		}
		if i == 15 {
			fmt.Println("Unable to reach Docker Daemon after 15 attempts.")
			break
		}
		time.Sleep(time.Second * 1)
	}
	// docker login
	// for debugging purposes, log the type of authentication
	// credentials that have been provided.
	switch {
	case args.Login.Password != "" && args.Login.Config != "":
		fmt.Println("Detected registry credentials and registry credentials file")
	case args.Login.Password != "":
		fmt.Println("Detected registry credentials")
	case args.Login.Config != "":
		fmt.Println("Detected registry credentials file")
	default:
		fmt.Println("Registry credentials or Docker config not provided. Guest mode enabled.")
	}

	// create Auth Config File
	if args.Login.Config != "" {
		os.MkdirAll(dockerHome, 0600)

		path := filepath.Join(dockerHome, "config.json")
		err := ioutil.WriteFile(path, []byte(args.Login.Config), 0600)
		if err != nil {
			return fmt.Errorf("error writing config.json: %s", err)
		}
	}

	// login to the Docker registry
	if args.Login.Password != "" {
		cmd := commandLogin(args.Login)
		raw, err := cmd.CombinedOutput()
		if err != nil {
			out := string(raw)
			out = strings.Replace(out, "WARNING! Using --password via the CLI is insecure. Use --password-stdin.", "", -1)
			fmt.Println(out)
			return fmt.Errorf("error authenticating: exit status 1")
		}
	}

	var cmds []*exec.Cmd
	if args.SnykToken != "" {
		cmds = append(cmds, snykLogin(args.SnykToken))
	} else {
		fmt.Println("Snyk credentials not provided. Unauthenticated mode only allows 10 scans a month")
	}

	cmds = append(cmds, scanResultsToFile(args.Image, args.Dockerfile, severityLevel))
	cmds = append(cmds, scan(args.Image, args.Dockerfile, severityLevel))
	// execute all commands in batch mode.
	for _, cmd := range cmds {
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		trace(cmd)

		err := cmd.Run()

		if err != nil {
			// required so it doesn't exit on scan file stage
			if !isCommandScanFile(cmd.Args) {
				if args.FailOnIssues {
					return err
				}
			} else {
				err = MapSummaryResults(results, args)
				if err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func MapSummaryResults(results ScanResults, args Args) error {
	card := drone.CardInput{
		Schema: "https://harness.github.io/card-templates/snyk.json",
	}
	data, err := os.ReadFile("/tmp/output.json")
	if err != nil {
		fmt.Println(err)
		return err
	}
	err = json.Unmarshal(data, &results)

	if err != nil {
		fmt.Printf(err.Error())
	}

	var summary ScanSummary
	err = json.Unmarshal(data, &summary)
	if err != nil {
		fmt.Printf(err.Error())
	}
	for _, v := range results.Vulnerabilities {
		switch v.Severity {
		case "critical":
			summary.Issues.Critical = summary.Issues.Critical + 1
		case "high":
			summary.Issues.High = summary.Issues.High + 1
		case "medium":
			summary.Issues.Medium = summary.Issues.Medium + 1
		case "low":
			summary.Issues.Low = summary.Issues.Low + 1
		}
	}
	r, err := json.Marshal(summary)
	card.Data = r
	file, err := json.Marshal(card)
	if err != nil {
		fmt.Println(err)
		return err
	}
	// support both writing to file location & encoded to logs
	path := args.CardFilePath
	switch {
	case path == "/dev/stdout":
		// !important - new line required otherwise TrimSuffix in runner won't work
		sEnc := fmt.Sprintf("%s%s%s%s", prefix, base64.StdEncoding.EncodeToString(file), suffix, "\n")
		err = ioutil.WriteFile("/dev/stdout", []byte(sEnc), 0644)
	case path != "":
		ioutil.WriteFile(path, file, 0644)
	}
	return nil
}

func commandLogin(login Login) *exec.Cmd {
	if login.Email != "" {
		return commandLoginEmail(login)
	}
	return exec.Command(
		dockerExe, "login",
		"-u", login.Username,
		"-p", login.Password,
		login.Registry,
	)
}

func commandLoginEmail(login Login) *exec.Cmd {
	return exec.Command(
		dockerExe, "login",
		"-u", login.Username,
		"-p", login.Password,
		"-e", login.Email,
		login.Registry,
	)
}

// helper function to create the docker info command.
func commandInfo() *exec.Cmd {
	return exec.Command(dockerExe, "info")
}

func scanResultsToFile(image, dockerfile, severityLevel string) *exec.Cmd {
	args := []string{
		"docker scan --json --group-issues",
	}
	if severityLevel != "" {
		args = append(args, "--severity="+severityLevel)
	}
	args = append(args, image)
	if dockerfile != "" {
		args = append(args, "--file="+dockerfile)
	}
	args = append(args, "> /tmp/output.json")

	return exec.Command(bashExe, "-c", strings.Join(args, " "))
}

func scan(image, dockerfile, severityLevel string) *exec.Cmd {
	args := []string{"scan"}
	if severityLevel != "" {
		args = append(args, "--severity="+severityLevel)
	}
	args = append(args, image)
	if dockerfile != "" {
		args = append(args, "--file="+dockerfile)
	}
	args = append(args, "--accept-license")
	return exec.Command(dockerExe, args...)
}

func snykLogin(token string) *exec.Cmd {
	args := []string{"scan", "--login"}
	args = append(args, "--token", token, "--accept-license")
	return exec.Command(dockerExe, args...)
}

// trace writes each command to stdout with the command wrapped in an xml
// tag so that it can be extracted and displayed in the logs.
func trace(cmd *exec.Cmd) {
	fmt.Fprintf(os.Stdout, "+ %s\n", strings.Join(cmd.Args, " "))
}

func isCommandScanFile(args []string) bool {
	return args[0] == "/bin/sh"
}

// helper function to create the docker daemon command.
func commandDaemon(daemon Daemon) *exec.Cmd {
	args := []string{
		"--data-root", daemon.StoragePath,
		"--host=unix:///var/run/docker.sock",
	}

	if _, err := os.Stat("/etc/docker/default.json"); err == nil {
		args = append(args, "--seccomp-profile=/etc/docker/default.json")
	}

	if daemon.StorageDriver != "" {
		args = append(args, "-s", daemon.StorageDriver)
	}
	if daemon.Insecure && daemon.PluginRegistry != "" {
		args = append(args, "--insecure-registry", daemon.PluginRegistry)
	}
	if daemon.IPv6 {
		args = append(args, "--ipv6")
	}
	if len(daemon.Mirror) != 0 {
		args = append(args, "--registry-mirror", daemon.Mirror)
	}
	if len(daemon.Bip) != 0 {
		args = append(args, "--bip", daemon.Bip)
	}
	for _, dns := range daemon.DNS {
		args = append(args, "--dns", dns)
	}
	for _, dnsSearch := range daemon.DNSSearch {
		args = append(args, "--dns-search", dnsSearch)
	}
	if len(daemon.MTU) != 0 {
		args = append(args, "--mtu", daemon.MTU)
	}
	if daemon.Experimental {
		args = append(args, "--experimental")
	}
	return exec.Command(dockerdExe, args...)
}

func startDaemon(d Daemon) {
	cmd := commandDaemon(d)
	if d.Debug {
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	} else {
		cmd.Stdout = ioutil.Discard
		cmd.Stderr = ioutil.Discard
	}
	go func() {
		trace(cmd)
		cmd.Run()
	}()
}
