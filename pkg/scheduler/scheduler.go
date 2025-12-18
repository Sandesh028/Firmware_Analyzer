package scheduler

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Options configures the scheduler behaviour.
type Options struct {
	AnalyzerPath   string
	Concurrency    int
	Logger         *log.Logger
	LocalExecutor  Executor
	RemoteExecutor Executor
	RemoteHosts    map[string]RemoteHost
}

// RemoteHost describes an execution target that runs analyses over SSH.
type RemoteHost struct {
	Name         string
	Address      string
	User         string
	AnalyzerPath string
	SSHBinary    string
}

// Job represents a firmware analysis to run.
type Job struct {
	ID             string   `json:"id"`
	Firmware       string   `json:"firmware"`
	OutputDir      string   `json:"output_dir"`
	HistoryDir     string   `json:"history_dir,omitempty"`
	ReportFormats  []string `json:"report_formats,omitempty"`
	BaselineReport string   `json:"baseline_report,omitempty"`
	DiffFormats    []string `json:"diff_formats,omitempty"`
	ExtraArgs      []string `json:"extra_args,omitempty"`
	RemoteHost     string   `json:"remote_host,omitempty"`
	TimeoutSeconds int      `json:"timeout_seconds,omitempty"`
}

// Result captures the outcome of a scheduled job.
type Result struct {
	JobID      string    `json:"job_id"`
	Firmware   string    `json:"firmware"`
	OutputDir  string    `json:"output_dir"`
	RemoteHost string    `json:"remote_host,omitempty"`
	Started    time.Time `json:"started"`
	Completed  time.Time `json:"completed"`
	Command    []string  `json:"command"`
	Error      string    `json:"error,omitempty"`
}

// Executor runs a command for local or remote execution targets.
type Executor interface {
	Run(ctx context.Context, name string, args ...string) error
}

// ExecFunc adapts a function to the Executor interface.
type ExecFunc func(ctx context.Context, name string, args ...string) error

// Run executes the command using the underlying function.
func (f ExecFunc) Run(ctx context.Context, name string, args ...string) error {
	return f(ctx, name, args...)
}

// Scheduler orchestrates batched firmware analyses across workers.
type Scheduler struct {
	opts      Options
	logger    *log.Logger
	jobs      chan Job
	results   chan Result
	wg        sync.WaitGroup
	started   bool
	startMu   sync.Mutex
	closeOnce sync.Once
	counter   uint64
}

// New constructs a Scheduler with sensible defaults.
func New(opts Options) *Scheduler {
	if opts.Concurrency <= 0 {
		opts.Concurrency = 1
	}
	if opts.AnalyzerPath == "" {
		opts.AnalyzerPath = "analyzer"
	}
	if opts.Logger == nil {
		opts.Logger = log.New(io.Discard, "scheduler", log.LstdFlags)
	}
	if opts.LocalExecutor == nil {
		opts.LocalExecutor = defaultExecutor(opts.Logger)
	}
	if opts.RemoteExecutor == nil {
		opts.RemoteExecutor = opts.LocalExecutor
	}
	if opts.RemoteHosts == nil {
		opts.RemoteHosts = make(map[string]RemoteHost)
	}
	return &Scheduler{opts: opts, logger: opts.Logger, jobs: make(chan Job)}
}

// Start launches the worker pool and returns a channel streaming job results.
func (s *Scheduler) Start(ctx context.Context) <-chan Result {
	s.startMu.Lock()
	defer s.startMu.Unlock()
	if s.started {
		return s.results
	}
	s.started = true
	s.results = make(chan Result)
	for i := 0; i < s.opts.Concurrency; i++ {
		s.wg.Add(1)
		go s.worker(ctx)
	}
	return s.results
}

// Enqueue schedules a job for execution.
func (s *Scheduler) Enqueue(job Job) error {
	if job.Firmware == "" {
		return fmt.Errorf("job missing firmware path")
	}
	if !s.started {
		return errors.New("scheduler not started")
	}
	if job.ID == "" {
		job.ID = s.nextID()
	}
	s.jobs <- job
	return nil
}

// Close waits for workers to finish and closes the result channel.
func (s *Scheduler) Close() {
	s.closeOnce.Do(func() {
		close(s.jobs)
		s.wg.Wait()
		close(s.results)
	})
}

func (s *Scheduler) worker(ctx context.Context) {
	defer s.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case job, ok := <-s.jobs:
			if !ok {
				return
			}
			result := s.runJob(ctx, job)
			select {
			case <-ctx.Done():
				return
			case s.results <- result:
			}
		}
	}
}

func (s *Scheduler) runJob(ctx context.Context, job Job) Result {
	start := time.Now().UTC()
	args := s.buildArgs(job)
	result := Result{
		JobID:      job.ID,
		Firmware:   job.Firmware,
		OutputDir:  job.OutputDir,
		RemoteHost: job.RemoteHost,
		Started:    start,
		Command:    args,
	}
	execCtx := ctx
	cancel := func() {}
	if job.TimeoutSeconds > 0 {
		execCtx, cancel = context.WithTimeout(ctx, time.Duration(job.TimeoutSeconds)*time.Second)
	}
	defer cancel()

	var err error
	if job.RemoteHost == "" {
		err = s.opts.LocalExecutor.Run(execCtx, s.opts.AnalyzerPath, args...)
		result.Command = append([]string{s.opts.AnalyzerPath}, args...)
	} else {
		host, ok := s.opts.RemoteHosts[job.RemoteHost]
		if !ok {
			err = fmt.Errorf("unknown remote host %q", job.RemoteHost)
		} else {
			target := host.Address
			if host.User != "" {
				target = host.User + "@" + host.Address
			}
			sshBin := host.SSHBinary
			if sshBin == "" {
				sshBin = "ssh"
			}
			remoteAnalyzer := host.AnalyzerPath
			if remoteAnalyzer == "" {
				remoteAnalyzer = s.opts.AnalyzerPath
			}
			cmdArgs := append([]string{target, remoteAnalyzer}, args...)
			result.Command = append([]string{sshBin}, cmdArgs...)
			err = s.opts.RemoteExecutor.Run(execCtx, sshBin, cmdArgs...)
		}
	}
	result.Completed = time.Now().UTC()
	if err != nil {
		result.Error = err.Error()
	}
	return result
}

func (s *Scheduler) buildArgs(job Job) []string {
	var args []string
	args = append(args, "--fw", job.Firmware)
	if job.OutputDir != "" {
		args = append(args, "--out", job.OutputDir)
	}
	if job.HistoryDir != "" {
		args = append(args, "--history-dir", job.HistoryDir)
	}
	if len(job.ReportFormats) > 0 {
		args = append(args, "--report-formats", strings.Join(job.ReportFormats, ","))
	}
	if job.BaselineReport != "" {
		args = append(args, "--baseline-report", job.BaselineReport)
	}
	if len(job.DiffFormats) > 0 {
		args = append(args, "--diff-formats", strings.Join(job.DiffFormats, ","))
	}
	if len(job.ExtraArgs) > 0 {
		args = append(args, job.ExtraArgs...)
	}
	return args
}

func (s *Scheduler) nextID() string {
	id := atomic.AddUint64(&s.counter, 1)
	return fmt.Sprintf("job-%d", id)
}

func defaultExecutor(logger *log.Logger) Executor {
	return ExecFunc(func(ctx context.Context, name string, args ...string) error {
		cmd := exec.CommandContext(ctx, name, args...)
		if logger != nil {
			writer := logger.Writer()
			if closer, ok := writer.(io.Closer); ok {
				defer closer.Close()
			}
			cmd.Stdout = writer
			cmd.Stderr = writer
		}
		return cmd.Run()
	})
}

// ResolveReportDir determines the path used for report outputs when a job completes.
func ResolveReportDir(paths []string) string {
	for _, path := range paths {
		if path == "" {
			continue
		}
		if filepath.Ext(path) != "" {
			return filepath.Dir(path)
		}
	}
	return ""
}
