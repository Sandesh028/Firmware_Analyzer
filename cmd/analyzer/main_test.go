package main

import (
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"firmwareanalyzer/pkg/diff"
	"firmwareanalyzer/pkg/report"
)

func TestSnapshotRunCreatesSnapshotDirectory(t *testing.T) {
	t.Parallel()

	originalWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Chdir(originalWD)
	})

	tmp := t.TempDir()
	if err := os.Chdir(tmp); err != nil {
		t.Fatalf("chdir: %v", err)
	}

	reportDir := filepath.Join(tmp, "out")
	if err := os.MkdirAll(reportDir, 0o755); err != nil {
		t.Fatalf("mkdir out: %v", err)
	}

	reportPaths := report.Paths{
		Markdown: filepath.Join(reportDir, "report.md"),
		HTML:     filepath.Join(reportDir, "report.html"),
		JSON:     filepath.Join(reportDir, "report.json"),
	}
	for _, p := range []string{reportPaths.Markdown, reportPaths.HTML, reportPaths.JSON} {
		if err := os.WriteFile(p, []byte("content"), 0o644); err != nil {
			t.Fatalf("write %s: %v", p, err)
		}
	}

	diffPaths := &diff.Paths{
		Markdown: filepath.Join(reportDir, "diff.md"),
		JSON:     filepath.Join(reportDir, "diff.json"),
	}
	for _, p := range []string{diffPaths.Markdown, diffPaths.JSON} {
		if err := os.WriteFile(p, []byte("diff"), 0o644); err != nil {
			t.Fatalf("write diff %s: %v", p, err)
		}
	}

	logger := log.New(io.Discard, "", 0)
	if err := snapshotRun(logger, "firmware.bin", reportDir, reportPaths, nil, nil, diffPaths); err != nil {
		t.Fatalf("snapshot run: %v", err)
	}

	snapshotDir := filepath.Join(tmp, "FA_firmware.bin")
	if _, err := os.Stat(snapshotDir); err != nil {
		t.Fatalf("snapshot directory missing: %v", err)
	}

	expected := []string{"report.md", "report.html", "report.json", "diff.md", "diff.json", "README.txt"}
	for _, name := range expected {
		if _, err := os.Stat(filepath.Join(snapshotDir, name)); err != nil {
			t.Fatalf("expected artefact %s: %v", name, err)
		}
	}
}

func TestSanitizeNameStripsUnsafeCharacters(t *testing.T) {
	t.Parallel()

	input := "../weird firmware.bin"
	got := sanitizeName(input)
	if got == "" || got == input || got == ".." {
		t.Fatalf("sanitizeName produced unsafe value: %q", got)
	}
	if strings.Contains(got, " ") || strings.Contains(got, "..") || strings.Contains(got, "/") {
		t.Fatalf("sanitizeName did not remove unsafe characters: %q", got)
	}
}
