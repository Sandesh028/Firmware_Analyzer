package plugin

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Finding represents a single plugin-reported issue.
type Finding struct {
	Plugin   string         `json:"plugin"`
	Summary  string         `json:"summary"`
	Severity string         `json:"severity,omitempty"`
	Details  map[string]any `json:"details,omitempty"`
}

// Result captures the outcome of running a plugin executable.
type Result struct {
	Plugin   string    `json:"plugin"`
	Findings []Finding `json:"findings,omitempty"`
	Error    string    `json:"error,omitempty"`
}

// Options tune plugin discovery and execution.
type Options struct {
	Directory string
	Timeout   time.Duration
	Env       map[string]string
}

// Runner executes external plugin scripts and collects JSON-formatted findings.
type Runner struct {
	logger *log.Logger
	opts   Options
}

// NewRunner instantiates a Runner, discarding logs when logger is nil.
func NewRunner(logger *log.Logger, opts Options) *Runner {
	if logger == nil {
		logger = log.New(io.Discard, "plugin", log.LstdFlags)
	}
	if opts.Timeout == 0 {
		opts.Timeout = 30 * time.Second
	}
	return &Runner{logger: logger, opts: opts}
}

// Run executes each executable file within the configured directory, treating
// stdout as a JSON array of findings. Errors encountered while running or
// decoding a plugin are captured in the corresponding Result.Error field.
func (r *Runner) Run(ctx context.Context, root string) ([]Result, error) {
	if strings.TrimSpace(r.opts.Directory) == "" {
		return nil, nil
	}
	entries, err := os.ReadDir(r.opts.Directory)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read plugin dir: %w", err)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })

	var results []Result
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			r.logger.Printf("stat plugin %s: %v", entry.Name(), err)
			continue
		}
		if info.Mode()&0o111 == 0 {
			continue
		}
		path := filepath.Join(r.opts.Directory, entry.Name())
		result := r.runPlugin(ctx, path, root)
		results = append(results, result)
	}
	return results, nil
}

func (r *Runner) runPlugin(ctx context.Context, path, root string) Result {
	name := filepath.Base(path)
	ctx, cancel := context.WithTimeout(ctx, r.opts.Timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, path)
	cmd.Env = append(os.Environ(), "ANALYZER_ROOT="+root)
	for key, value := range r.opts.Env {
		cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", key, value))
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		msg := err.Error()
		if stderr.Len() > 0 {
			msg = fmt.Sprintf("%s: %s", msg, strings.TrimSpace(stderr.String()))
		}
		return Result{Plugin: name, Error: msg}
	}

	if stdout.Len() == 0 {
		return Result{Plugin: name}
	}

	var findings []Finding
	if decodeErr := json.NewDecoder(&stdout).Decode(&findings); decodeErr != nil {
		return Result{Plugin: name, Error: fmt.Sprintf("decode JSON: %v", decodeErr)}
	}
	for i := range findings {
		findings[i].Plugin = name
	}
	return Result{Plugin: name, Findings: findings}
}
