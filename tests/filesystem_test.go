package tests

import (
	"context"
	"os"
	"path/filepath"
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
