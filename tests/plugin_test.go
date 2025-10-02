package tests

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"firmwareanalyzer/pkg/plugin"
)

func TestPluginRunnerExecutesScripts(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell scripts not supported on Windows in tests")
	}
	t.Parallel()

	dir := t.TempDir()
	script := filepath.Join(dir, "sample.sh")
	content := "#!/bin/sh\nprintf '[{\"summary\":\"ok\",\"severity\":\"low\"}]'"
	if err := os.WriteFile(script, []byte(content), 0o755); err != nil {
		t.Fatalf("write script: %v", err)
	}

	runner := plugin.NewRunner(nil, plugin.Options{Directory: dir})
	results, err := runner.Run(context.Background(), t.TempDir())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected single plugin result, got %d", len(results))
	}
	if len(results[0].Findings) != 1 || results[0].Findings[0].Summary != "ok" {
		t.Fatalf("unexpected findings: %#v", results[0].Findings)
	}
}

func TestPluginRunnerCapturesErrors(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell scripts not supported on Windows in tests")
	}
	t.Parallel()

	dir := t.TempDir()
	script := filepath.Join(dir, "fail.sh")
	content := "#!/bin/sh\necho error >&2\nexit 1"
	if err := os.WriteFile(script, []byte(content), 0o755); err != nil {
		t.Fatalf("write script: %v", err)
	}

	runner := plugin.NewRunner(nil, plugin.Options{Directory: dir})
	results, err := runner.Run(context.Background(), t.TempDir())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(results) != 1 || results[0].Error == "" {
		t.Fatalf("expected plugin error to be captured: %#v", results)
	}
}
