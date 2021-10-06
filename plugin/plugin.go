// Copyright 2020 the Drone Authors. All rights reserved.
// Use of this source code is governed by the Blue Oak Model License
// that can be found in the LICENSE file.

package plugin

import (
	"context"
	"encoding/json"
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
const bashExe = "/bin/sh"

type (
	// Login defines Docker  parameters.
	Login struct {
		Registry string `envconfig:"PLUGIN_REGISTRY" default:"https://index.docker.io/v1/"` // Docker registry address
		Username string `envconfig:"PLUGIN_USERNAME" required:"true"`                       // Docker registry username
		Password string `envconfig:"PLUGIN_PASSWORD" required:"true"`                       // Docker registry password
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

	scanResults struct {
		Vulnerabilities []interface{} `json:"vulnerabilities"`
		Ok              bool          `json:"ok"`
		DependencyCount int           `json:"dependencyCount"`
		Org             string        `json:"org"`
		Policy          string        `json:"policy"`
		IsPrivate       bool          `json:"isPrivate"`
		LicensesPolicy  struct {
			Severities struct {
			} `json:"severities"`
			OrgLicenseRules struct {
				AGPL10 struct {
					LicenseType  string `json:"licenseType"`
					Severity     string `json:"severity"`
					Instructions string `json:"instructions"`
				} `json:"AGPL-1.0"`
				AGPL30 struct {
					LicenseType  string `json:"licenseType"`
					Severity     string `json:"severity"`
					Instructions string `json:"instructions"`
				} `json:"AGPL-3.0"`
				Artistic10 struct {
					LicenseType  string `json:"licenseType"`
					Severity     string `json:"severity"`
					Instructions string `json:"instructions"`
				} `json:"Artistic-1.0"`
				Artistic20 struct {
					LicenseType  string `json:"licenseType"`
					Severity     string `json:"severity"`
					Instructions string `json:"instructions"`
				} `json:"Artistic-2.0"`
				CDDL10 struct {
					LicenseType  string `json:"licenseType"`
					Severity     string `json:"severity"`
					Instructions string `json:"instructions"`
				} `json:"CDDL-1.0"`
				CPOL102 struct {
					LicenseType  string `json:"licenseType"`
					Severity     string `json:"severity"`
					Instructions string `json:"instructions"`
				} `json:"CPOL-1.02"`
				EPL10 struct {
					LicenseType  string `json:"licenseType"`
					Severity     string `json:"severity"`
					Instructions string `json:"instructions"`
				} `json:"EPL-1.0"`
				GPL20 struct {
					LicenseType  string `json:"licenseType"`
					Severity     string `json:"severity"`
					Instructions string `json:"instructions"`
				} `json:"GPL-2.0"`
				GPL30 struct {
					LicenseType  string `json:"licenseType"`
					Severity     string `json:"severity"`
					Instructions string `json:"instructions"`
				} `json:"GPL-3.0"`
				LGPL20 struct {
					LicenseType  string `json:"licenseType"`
					Severity     string `json:"severity"`
					Instructions string `json:"instructions"`
				} `json:"LGPL-2.0"`
				LGPL21 struct {
					LicenseType  string `json:"licenseType"`
					Severity     string `json:"severity"`
					Instructions string `json:"instructions"`
				} `json:"LGPL-2.1"`
				LGPL30 struct {
					LicenseType  string `json:"licenseType"`
					Severity     string `json:"severity"`
					Instructions string `json:"instructions"`
				} `json:"LGPL-3.0"`
				MPL11 struct {
					LicenseType  string `json:"licenseType"`
					Severity     string `json:"severity"`
					Instructions string `json:"instructions"`
				} `json:"MPL-1.1"`
				MPL20 struct {
					LicenseType  string `json:"licenseType"`
					Severity     string `json:"severity"`
					Instructions string `json:"instructions"`
				} `json:"MPL-2.0"`
				MSRL struct {
					LicenseType  string `json:"licenseType"`
					Severity     string `json:"severity"`
					Instructions string `json:"instructions"`
				} `json:"MS-RL"`
				SimPL20 struct {
					LicenseType  string `json:"licenseType"`
					Severity     string `json:"severity"`
					Instructions string `json:"instructions"`
				} `json:"SimPL-2.0"`
			} `json:"orgLicenseRules"`
		} `json:"licensesPolicy"`
		PackageManager string      `json:"packageManager"`
		IgnoreSettings interface{} `json:"ignoreSettings"`
		Docker         struct {
			BaseImageRemediation struct {
				Code   string `json:"code"`
				Advice []struct {
					Message string `json:"message"`
					Bold    bool   `json:"bold"`
					Color   string `json:"color"`
				} `json:"advice"`
			} `json:"baseImageRemediation"`
		} `json:"docker"`
		Summary          string `json:"summary"`
		FilesystemPolicy bool   `json:"filesystemPolicy"`
		UniqueCount      int    `json:"uniqueCount"`
		ProjectName      string `json:"projectName"`
		Platform         string `json:"platform"`
		ScanResult       struct {
			Facts []struct {
				Type string `json:"type"`
				Data struct {
					SchemaVersion string `json:"schemaVersion"`
					PkgManager    struct {
						Name         string `json:"name"`
						Repositories []struct {
							Alias string `json:"alias"`
						} `json:"repositories"`
					} `json:"pkgManager"`
					Pkgs []struct {
						ID   string `json:"id"`
						Info struct {
							Name    string `json:"name"`
							Version string `json:"version"`
						} `json:"info"`
					} `json:"pkgs"`
					Graph struct {
						RootNodeID string `json:"rootNodeId"`
						Nodes      []struct {
							NodeID string        `json:"nodeId"`
							PkgID  string        `json:"pkgId"`
							Deps   []interface{} `json:"deps"`
						} `json:"nodes"`
					} `json:"graph"`
				} `json:"data"`
			} `json:"facts"`
			Target struct {
				Image string `json:"image"`
			} `json:"target"`
			Identity struct {
				Type string `json:"type"`
				Args struct {
					Platform string `json:"platform"`
				} `json:"args"`
			} `json:"identity"`
		} `json:"scanResult"`
		Path string `json:"path"`
	}
)

// Args provides plugin execution arguments.
type Args struct {
	Pipeline
	Login      Login
	Daemon     Daemon
	Level      string `envconfig:"PLUGIN_LOG_LEVEL"`
	Dockerfile string `envconfig:"PLUGIN_DOCKERFILE" required:"true"`
	Image      string `envconfig:"PLUGIN_IMAGE" required:"true"`
	AuthToken  string `envconfig:"PLUGIN_SNYK"`
	Severity   string `envconfig:"PLUGIN_SEVERITY"`
}

// Exec executes the plugin.
func Exec(ctx context.Context, args Args) error {
	if !args.Daemon.Disabled {
		startDaemon(args.Daemon)
	}

	fmt.Printf("Current Unix Time: %v\n", time.Now().Unix())
	var results scanResults
	severityLevel := strings.ToLower(args.Severity)
	switch severityLevel {
	case "critical",
		"high",
		"medium",
		"low":
		fmt.Printf("Severity level set at %s\n", severityLevel)
	case "":
		fmt.Printf("Severity level not set.")
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
	if args.AuthToken != "" {
		cmds = append(cmds, snykLogin(args.AuthToken))
	} else {
		fmt.Println("Snyk credentials not provided. Unauthenticated mode only allows 10 scans a month")
	}
	cmds = append(cmds, scan(args.Image, args.Dockerfile, severityLevel))
	cmds = append(cmds, scanResultsToFile(args.Image, args.Dockerfile, severityLevel))
	// execute all commands in batch mode.
	for _, cmd := range cmds {
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		trace(cmd)

		err := cmd.Run()

		if err != nil {
			fmt.Println(err)
			//return err
		}
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
		"docker scan --json",
	}
	if severityLevel != "" {
		args = append(args, "--severity="+severityLevel)
	}
	args = append(args,
		image,
		"--file",
		dockerfile,
		"> /tmp/output.json")
	return exec.Command(bashExe, "-c", strings.Join(args," "))
}

func scan(image, dockerfile, severityLevel string) *exec.Cmd {
	args := []string{
		"scan"}
	if severityLevel != "" {
		args = append(args, "--severity="+severityLevel)
	}
	args = append(args,
		image,
		"--file",
		dockerfile,
		"--accept-license")
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
