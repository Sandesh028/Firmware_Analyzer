package tests

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"firmwareanalyzer/pkg/binaryinspector"
)

func TestInspectDetectsELFBinary(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	src := filepath.Join(tmp, "main.go")
	if err := os.WriteFile(src, []byte("package main\nfunc main(){}\n"), 0o644); err != nil {
		t.Fatalf("write source: %v", err)
	}

	binPath := filepath.Join(tmp, "firmware")
	cmd := exec.Command("go", "build", "-o", binPath, src)
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH=amd64")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build test binary: %v, output: %s", err, out)
	}

	inspector := binaryinspector.NewInspector(nil)
	results, err := inspector.Inspect(context.Background(), tmp)
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}

	var found bool
	for _, res := range results {
		if res.Path == binPath {
			found = true
			if res.Err != "" {
				t.Fatalf("unexpected error in result: %s", res.Err)
			}
			if res.Architecture == "" {
				t.Fatalf("architecture not detected: %+v", res)
			}
		}
	}

	if !found {
		t.Fatalf("expected to find binary at %s", binPath)
	}
}

func TestCollectMarkdownTable(t *testing.T) {
	results := []binaryinspector.Result{{
		Path:         "/tmp/bin",
		Type:         "ET_DYN",
		Architecture: "EM_X86_64",
		RELRO:        binaryinspector.RELROFull,
		NXEnabled:    true,
		PIEEnabled:   true,
		Stripped:     false,
	}}

	table := binaryinspector.CollectMarkdownTable(results)
	if table == "" {
		t.Fatal("expected non-empty table")
	}
	if got, want := table[:1], "|"; got != want {
		t.Fatalf("table must start with '|' got %q", got)
	}
}
