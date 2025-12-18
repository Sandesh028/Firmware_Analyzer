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

	"firmwareanalyzer/pkg/binaryinspector"
	"firmwareanalyzer/pkg/configparser"
	"firmwareanalyzer/pkg/extractor"
	"firmwareanalyzer/pkg/filesystem"
	"firmwareanalyzer/pkg/secrets"
	"firmwareanalyzer/pkg/service"
	"firmwareanalyzer/pkg/vuln"
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
	Directory      string
	Timeout        time.Duration
	Env            map[string]string
	MaxOutputBytes int64
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
	if opts.MaxOutputBytes <= 0 {
		opts.MaxOutputBytes = 1 << 20 // 1MiB default stdout cap
	}
	return &Runner{logger: logger, opts: opts}
}

// Metadata summarises the workspace for plugins. It is serialised to JSON and
// provided on stdin to each plugin invocation so that external checks can make
// informed decisions without re-scanning the filesystem.
type Metadata struct {
	Firmware        string                   `json:"firmware"`
	Root            string                   `json:"root"`
	Partitions      []extractor.Partition    `json:"partitions,omitempty"`
	FileSystems     []filesystem.Mount       `json:"filesystems,omitempty"`
	Configs         []configparser.Finding   `json:"configs,omitempty"`
	Services        []service.Service        `json:"services,omitempty"`
	Secrets         []secrets.Finding        `json:"secrets,omitempty"`
	Binaries        []binaryinspector.Result `json:"binaries,omitempty"`
	Vulnerabilities []vuln.Finding           `json:"vulnerabilities,omitempty"`
	PackageVulns    []vuln.PackageFinding    `json:"package_vulnerabilities,omitempty"`
}

// Run executes each executable file within the configured directory, treating
// stdout as a JSON array of findings. Structured workspace metadata is provided
// to plugins via stdin as JSON. Errors encountered while running or decoding a
// plugin are captured in the corresponding Result.Error field.
func (r *Runner) Run(ctx context.Context, meta Metadata) ([]Result, error) {
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

	payload, err := json.Marshal(meta)
	if err != nil {
		return nil, fmt.Errorf("encode metadata: %w", err)
	}

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
		result := r.runPlugin(ctx, path, payload, meta.Root)
		results = append(results, result)
	}
	return results, nil
}

func (r *Runner) runPlugin(ctx context.Context, path string, payload []byte, root string) Result {
	name := filepath.Base(path)
	ctx, cancel := context.WithTimeout(ctx, r.opts.Timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, path)
	cmd.Env = append(os.Environ(), "ANALYZER_ROOT="+root)
	for key, value := range r.opts.Env {
		cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", key, value))
	}
	cmd.Env = append(cmd.Env, "ANALYZER_METADATA_FORMAT=json")
	cmd.Stdin = bytes.NewReader(payload)

	stdout := newLimitedBuffer(r.opts.MaxOutputBytes)
	stderr := newLimitedBuffer(128 << 10)
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	err := cmd.Run()
	if err != nil {
		msg := err.Error()
		if stderr.Len() > 0 {
			msg = fmt.Sprintf("%s: %s", msg, strings.TrimSpace(stderr.String()))
		}
		if stderr.Truncated() {
			msg += " (stderr truncated)"
		}
		return Result{Plugin: name, Error: msg}
	}

	if stdout.Len() == 0 {
		return Result{Plugin: name}
	}

	if stdout.Truncated() {
		return Result{Plugin: name, Error: "stdout truncated"}
	}

	var findings []Finding
	if decodeErr := json.NewDecoder(bytes.NewReader(stdout.Bytes())).Decode(&findings); decodeErr != nil {
		return Result{Plugin: name, Error: fmt.Sprintf("decode JSON: %v", decodeErr)}
	}
	for i := range findings {
		findings[i].Plugin = name
	}
	return Result{Plugin: name, Findings: findings}
}

type limitedBuffer struct {
	buf       bytes.Buffer
	max       int64
	truncated bool
}

func newLimitedBuffer(max int64) *limitedBuffer {
	return &limitedBuffer{max: max}
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if b.max <= 0 {
		return b.buf.Write(p)
	}
	if int64(b.buf.Len()+len(p)) <= b.max {
		return b.buf.Write(p)
	}
	allowed := int(b.max) - b.buf.Len()
	if allowed < 0 {
		allowed = 0
	}
	if allowed > 0 {
		b.buf.Write(p[:allowed])
	}
	b.truncated = true
	return len(p), nil
}

func (b *limitedBuffer) Len() int {
	return b.buf.Len()
}

func (b *limitedBuffer) Bytes() []byte {
	return b.buf.Bytes()
}

func (b *limitedBuffer) String() string {
	return b.buf.String()
}

func (b *limitedBuffer) Truncated() bool {
	return b.truncated
}
