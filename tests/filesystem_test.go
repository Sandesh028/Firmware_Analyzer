package tests

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"firmwareanalyzer/pkg/filesystem"
)

func TestFilesystemDetectorRecognisesMagic(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	squash := filepath.Join(root, "rootfs.squashfs")
	if err := os.WriteFile(squash, []byte("hsqs"), 0o644); err != nil {
		t.Fatalf("write squashfs: %v", err)
	}

	detector := filesystem.NewDetector(nil)
	mounts, err := detector.Detect(context.Background(), root)
	if err != nil {
		t.Fatalf("detect: %v", err)
	}

	var found bool
	for _, mnt := range mounts {
		if mnt.ImagePath == squash && mnt.Type == "squashfs" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected squashfs mount in %#v", mounts)
	}
}

func TestFilesystemDetectorSkipsNestedDirectories(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "upper", "nested"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	detector := filesystem.NewDetector(nil)
	mounts, err := detector.Detect(context.Background(), root)
	if err != nil {
		t.Fatalf("detect: %v", err)
	}

	var hasUpper, hasNested bool
	for _, mnt := range mounts {
		if strings.Contains(mnt.ImagePath, "nested") {
			hasNested = true
		}
		if strings.HasSuffix(mnt.ImagePath, "upper") {
			hasUpper = true
		}
	}
	if !hasUpper {
		t.Fatalf("expected upper directory mount in %#v", mounts)
	}
	if hasNested {
		t.Fatalf("unexpected nested directory mount in %#v", mounts)
	}
}
