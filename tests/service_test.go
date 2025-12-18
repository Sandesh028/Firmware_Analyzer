package tests

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"firmwareanalyzer/pkg/service"
)

func TestServiceDetectorFindsInitScripts(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	initDir := filepath.Join(root, "etc", "init.d")
	if err := os.MkdirAll(initDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	script := filepath.Join(initDir, "S10daemon")
	if err := os.WriteFile(script, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("write script: %v", err)
	}

	detector := service.NewDetector(nil)
	services, err := detector.Detect(context.Background(), root)
	if err != nil {
		t.Fatalf("detect: %v", err)
	}

	if len(services) == 0 {
		t.Fatalf("expected services, got %#v", services)
	}
}
