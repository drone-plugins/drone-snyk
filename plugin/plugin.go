// Copyright 2020 the Drone Authors. All rights reserved.
// Use of this source code is governed by the Blue Oak Model License
// that can be found in the LICENSE file.

package plugin

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const dockerExe = "/usr/local/bin/docker"
const dockerdExe = "/usr/local/bin/dockerd"
const dockerHome = "/root/.docker/"

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
				Bold    bool   `json:"bold"`
				Color   string `json:"color,omitempty"`
			} `json:"advice"`
		} `json:"baseImageRemediation"`
	}

	ScanResults struct {
		Vulnerabilities []struct {
			PackageName          string `json:"packageName,omitempty"`
			Severity             string `json:"severity,omitempty"`
			SeverityWithCritical string `json:"severityWithCritical,omitempty"`
		} `json:"vulnerabilities,omitempty"`
	}

	ScanSummary struct {
		Issues struct {
			Critical int64 `json:"critical"`
			High     int64 `json:"high"`
			Medium   int64 `json:"medium"`
			Low      int64 `json:"low"`
		}
		Docker      ScanDocker `json:"docker,omitempty"`
		Summary     string     `json:"summary"`
		UniqueCount int        `json:"uniqueCount"`
		ProjectName string     `json:"projectName"`
		Platform    string     `json:"platform,omitempty"`
		Path        string     `json:"path"`
	}
)

// Args provides plugin execution arguments.
type Args struct {
	Pipeline
	Login             Login
	Daemon            Daemon
	Level             string `envconfig:"PLUGIN_LOG_LEVEL"`
	Dockerfile        string `envconfig:"PLUGIN_DOCKERFILE"`
	Image             string `envconfig:"PLUGIN_IMAGE" required:"true"`
	SnykToken         string `envconfig:"PLUGIN_SNYK"`
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

	severityLevel, err2 := checkSeverityLevel(args)
	if err2 != nil {
		return err2
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

	loginCmd := snykLogin(args.SnykToken)
	raw, err := loginCmd.CombinedOutput()
	if err != nil {
		out := string(raw)
		out = strings.Replace(out, "WARNING! Using --password via the CLI is insecure. Use --password-stdin.", "", -1)
		fmt.Println(out)
		return fmt.Errorf("error authenticating: exit status 1")
	}

	cmds = append(cmds, scan(args.Image, args.Dockerfile, severityLevel, false))
	// execute all commands in batch mode.
	for _, cmd := range cmds {
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		trace(cmd)

		err = cmd.Run()
		if args.FailOnIssues {
			return err
		}
	}

	if err := args.writeCard(); err != nil {
		fmt.Printf("Could not create adaptive card. %s\n", err)
	}
	return nil
}

func checkSeverityLevel(args Args) (string, error) {
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
		return "", fmt.Errorf("invalid severity level input, must be critical, high, medium or low")
	}
	return severityLevel, nil
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

func scan(image, dockerfile, severityLevel string, jsonFormat bool) *exec.Cmd {
	args := []string{"scan"}
	if jsonFormat {
		args = append(args, "--json")
		args = append(args, "--group-issues")
	}
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
