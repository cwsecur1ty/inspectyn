package webkit

import (
	"context"
	"fmt"
	"time"

	"github.com/cwsecur1ty/inspectyn/internal/inspect"
)

const HistoryLimit = 10

type Request struct {
	Kind        string   `json:"kind"`
	Targets     []string `json:"targets"`
	DNS         bool     `json:"dns"`
	DNSDetails  bool     `json:"dnsDetails"`
	SecurityTXT bool     `json:"securityTxt"`
	TimeoutMS   int      `json:"timeoutMs"`
	Concurrency int      `json:"concurrency"`
	FailOn      string   `json:"failOn"`
}

type Result struct {
	Report   *inspect.Report `json:"report,omitempty"`
	ExitCode int             `json:"exitCode"`
}

type Runner interface {
	Run(context.Context, Request) (Result, error)
}

func (request Request) config() inspect.Config {
	return inspect.Config{SchemaVersion: 1, Targets: request.Targets, DNS: request.DNS,
		DNSDetails: request.DNSDetails, SecurityTXT: request.SecurityTXT,
		TimeoutMS: request.TimeoutMS, Concurrency: request.Concurrency}
}

func ValidateRequest(request Request) (Request, error) {
	if request.Kind != "scan" && request.Kind != "recon" {
		return Request{}, fmt.Errorf("choose scan or recon")
	}
	if request.Kind == "recon" && request.SecurityTXT {
		return Request{}, fmt.Errorf("security.txt is available for HTTPS scans only")
	}
	switch request.FailOn {
	case "info", "low", "medium", "high", "critical", "none":
	default:
		return Request{}, fmt.Errorf("choose a valid severity threshold")
	}
	request.Targets = append([]string(nil), request.Targets...)
	if request.Kind == "recon" {
		for i, target := range request.Targets {
			normalized, err := inspect.NormalizeReconTarget(target)
			if err != nil {
				return Request{}, fmt.Errorf("target %d: %w", i+1, err)
			}
			request.Targets[i] = normalized
		}
	}
	config, err := inspect.ValidateConfig(request.config())
	if err != nil {
		return Request{}, err
	}
	request.Targets = config.Targets
	return request, nil
}

func runDeadline(request Request) time.Duration {
	phases := 2
	if request.SecurityTXT {
		phases++
	}
	// One hostname can serialize the whole list; allow every requested phase.
	return time.Duration(len(request.Targets)*request.TimeoutMS*phases)*time.Millisecond + 10*time.Second
}

type Job struct {
	ID         string          `json:"id"`
	Kind       string          `json:"kind"`
	Targets    []string        `json:"targets"`
	State      string          `json:"state"`
	CreatedAt  string          `json:"createdAt"`
	FinishedAt string          `json:"finishedAt,omitempty"`
	ExitCode   *int            `json:"exitCode,omitempty"`
	Error      string          `json:"error,omitempty"`
	Report     *inspect.Report `json:"report,omitempty"`
}
