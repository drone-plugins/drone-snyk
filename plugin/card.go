package plugin

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"io/ioutil"
	"os"
	"strings"

	"github.com/drone/drone-go/drone"
)

func (args Args) writeCard() error {
	cmd := scan(args.Image, args.Dockerfile, strings.ToLower(args.SeverityThreshold), true)
	data, err := cmd.CombinedOutput()
	if args.FailOnIssues {
		if err != nil {
			return err
		}
	}

	out := ScanResults{}
	if err = json.Unmarshal(data, &out); err != nil {
		return err
	}

	summary := ScanSummary{}
	if err = json.Unmarshal(data, &summary); err != nil {
		return err
	}

	for _, v := range out.Vulnerabilities {
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

	sum, err := json.Marshal(summary)
	card := drone.CardInput{
		Schema: "https://drone-plugins.github.io/drone-snyk/card.json",
		Data:   sum,
	}

	writeCard(args.CardFilePath, &card)
	return nil
}

func writeCard(path string, card interface{}) {
	data, _ := json.Marshal(card)
	switch {
	case path == "/dev/stdout":
		writeCardTo(os.Stdout, data)
	case path == "/dev/stderr":
		writeCardTo(os.Stderr, data)
	case path != "":
		ioutil.WriteFile(path, data, 0644)
	}
}

func writeCardTo(out io.Writer, data []byte) {
	encoded := base64.StdEncoding.EncodeToString(data)
	io.WriteString(out, "\u001B]1338;")
	io.WriteString(out, encoded)
	io.WriteString(out, "\u001B]0m")
	io.WriteString(out, "\n")
}
