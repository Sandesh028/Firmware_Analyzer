package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"firmwareanalyzer/pkg/scheduler"
)

type plan struct {
	Jobs []scheduler.Job `json:"jobs"`
}

func main() {
	planPath := flag.String("plan", "", "path to a JSON plan describing scheduled jobs")
	analyzerPath := flag.String("analyzer", "analyzer", "path to the analyzer binary")
	concurrency := flag.Int("concurrency", 2, "maximum concurrent analyses")
	defaultHistory := flag.String("history-dir", "", "default history directory for jobs missing one")
	var remoteHosts remoteHostsFlag
	flag.Var(&remoteHosts, "remote-host", "remote host definition (name=user@host[,analyzer=/path][,ssh=/path])")
	flag.Parse()

	if *planPath == "" {
		log.Fatal("missing required --plan file")
	}

	jobs, err := loadPlan(*planPath)
	if err != nil {
		log.Fatalf("load plan: %v", err)
	}
	if len(jobs) == 0 {
		log.Fatal("plan did not contain any jobs")
	}

	logger := log.New(os.Stdout, "scheduler ", log.LstdFlags)
	opts := scheduler.Options{
		AnalyzerPath: *analyzerPath,
		Concurrency:  *concurrency,
		Logger:       logger,
		RemoteHosts:  remoteHosts.toMap(),
	}
	sched := scheduler.New(opts)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	results := sched.Start(ctx)
	go func() {
		for res := range results {
			if res.Error != "" {
				logger.Printf("job %s (%s) failed: %s", res.JobID, res.Firmware, res.Error)
			} else {
				logger.Printf("job %s (%s) complete", res.JobID, res.Firmware)
			}
		}
	}()

	for i := range jobs {
		if *defaultHistory != "" && jobs[i].HistoryDir == "" {
			jobs[i].HistoryDir = *defaultHistory
		}
		if err := sched.Enqueue(jobs[i]); err != nil {
			log.Fatalf("enqueue job %d: %v", i, err)
		}
	}

	sched.Close()
	<-ctx.Done()
}

func loadPlan(path string) ([]scheduler.Job, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		return nil, errors.New("plan file was empty")
	}
	if strings.HasPrefix(trimmed, "[") {
		var jobs []scheduler.Job
		if err := json.Unmarshal(data, &jobs); err != nil {
			return nil, err
		}
		return jobs, nil
	}
	var p plan
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, err
	}
	return p.Jobs, nil
}

type remoteHostsFlag struct {
	hosts map[string]scheduler.RemoteHost
}

func (r *remoteHostsFlag) String() string {
	return ""
}

func (r *remoteHostsFlag) Set(value string) error {
	if r.hosts == nil {
		r.hosts = make(map[string]scheduler.RemoteHost)
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return errors.New("remote host definition cannot be empty")
	}
	parts := strings.Split(value, ",")
	namePair := strings.SplitN(parts[0], "=", 2)
	if len(namePair) != 2 {
		return fmt.Errorf("remote host must be in name=target form: %s", value)
	}
	name := strings.TrimSpace(namePair[0])
	target := strings.TrimSpace(namePair[1])
	if name == "" || target == "" {
		return fmt.Errorf("invalid remote host declaration: %s", value)
	}
	host := scheduler.RemoteHost{Name: name}
	if at := strings.Index(target, "@"); at >= 0 {
		host.User = target[:at]
		host.Address = target[at+1:]
	} else {
		host.Address = target
	}
	for _, segment := range parts[1:] {
		segment = strings.TrimSpace(segment)
		if segment == "" {
			continue
		}
		kv := strings.SplitN(segment, "=", 2)
		if len(kv) != 2 {
			return fmt.Errorf("invalid remote host attribute: %s", segment)
		}
		key := strings.TrimSpace(kv[0])
		val := strings.TrimSpace(kv[1])
		switch key {
		case "analyzer":
			host.AnalyzerPath = val
		case "ssh":
			host.SSHBinary = val
		default:
			return fmt.Errorf("unknown remote host attribute %s", key)
		}
	}
	r.hosts[name] = host
	return nil
}

func (r *remoteHostsFlag) toMap() map[string]scheduler.RemoteHost {
	if r.hosts == nil {
		return map[string]scheduler.RemoteHost{}
	}
	return r.hosts
}
