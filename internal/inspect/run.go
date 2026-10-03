package inspect

import (
	"context"
	"fmt"
	"net/url"
	"sync"
	"time"
)

type TargetCollector interface {
	Collect(context.Context, string, Config, string) (Observation, []CheckError)
}

func Run(ctx context.Context, kind string, config Config, collector TargetCollector) (Report, error) {
	if kind != "scan" && kind != "recon" {
		return Report{}, fmt.Errorf("command must be scan or recon")
	}
	config.Targets = append([]string(nil), config.Targets...)
	if kind == "recon" {
		for i, target := range config.Targets {
			normalized, err := NormalizeReconTarget(target)
			if err != nil {
				return Report{}, err
			}
			config.Targets[i] = normalized
		}
	}
	config, err := ValidateConfig(config)
	if err != nil {
		return Report{}, err
	}
	if collector == nil {
		collector = NewCollector()
	}
	type result struct {
		observation Observation
		errors      []CheckError
	}
	results := make([]result, len(config.Targets))
	jobs := make(chan int, len(config.Targets))
	hostSlots := map[string]chan struct{}{}
	for i, target := range config.Targets {
		parsed, _ := url.Parse(target)
		if hostSlots[parsed.Hostname()] == nil {
			hostSlots[parsed.Hostname()] = make(chan struct{}, 1)
		}
		jobs <- i
	}
	close(jobs)
	var workers sync.WaitGroup
	for range min(config.Concurrency, len(config.Targets)) {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for index := range jobs {
				target := config.Targets[index]
				parsed, _ := url.Parse(target)
				slot := hostSlots[parsed.Hostname()]
				select {
				case slot <- struct{}{}:
					if ctx.Err() == nil {
						results[index].observation, results[index].errors = collector.Collect(ctx, target, config, kind)
					} else {
						results[index].errors = []CheckError{{Target: target, Code: "CANCELLED", Message: "Check cancelled."}}
					}
					<-slot
				case <-ctx.Done():
					results[index].errors = []CheckError{{Target: target, Code: "CANCELLED", Message: "Check cancelled."}}
				}
			}
		}()
	}
	workers.Wait()
	now := time.Now().UTC()
	report := Report{SchemaVersion: 1, Tool: Tool{Name: "inspectyn", Version: Version}, Kind: kind,
		GeneratedAt: now.Format(time.RFC3339Nano), Complete: true, Targets: config.Targets,
		Findings: []Finding{}, Errors: []CheckError{}, Observations: []Observation{},
		Context: map[string]any{"dns": config.DNS, "concurrency": config.Concurrency,
			"maxTargets": 20, "timeoutMsPerPhase": config.TimeoutMS,
			"scope": "Exact configured names; no crawling, subdomain enumeration or redirect following."}}
	if kind == "recon" {
		report.Context["scope"] = "DNS records for exact configured names. No HTTPS requests or subdomain enumeration."
	}
	for _, result := range results {
		if result.observation.Hostname != "" {
			report.Observations = append(report.Observations, result.observation)
			report.Findings = append(report.Findings, EvaluateObservation(result.observation, now)...)
		}
		report.Errors = append(report.Errors, result.errors...)
		for _, checkError := range result.errors {
			if checkError.Code == "TLS_CERTIFICATE_INVALID" {
				report.Findings = append(report.Findings, Finding{RuleID: "SPECTYN_TLS_INVALID", Severity: "high",
					Title: "TLS certificate verification failed", Evidence: checkError.Message, Target: checkError.Target,
					Remediation: "Check the certificate hostname, validity and complete chain."})
			}
		}
	}
	if len(report.Errors) > 0 {
		report.Complete = false
	}
	for _, finding := range report.Findings {
		if finding.State == "Not assessable" {
			report.Complete = false
		}
	}
	return report, nil
}
