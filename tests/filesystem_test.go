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
			if mnt.Offset != 0 {
				t.Fatalf("expected zero offset for standalone squashfs, got %d", mnt.Offset)
			}
			if mnt.Notes == "" {
				t.Fatalf("expected notes for squashfs mount")
			}
			found = true
		}
	}
	if !found {
		t.Fatalf("expected squashfs mount in %#v", mounts)
	}
}

func TestFilesystemDetectorDetectsLikelyRootDirectories(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	nestedRoot := filepath.Join(root, "img", "rootfs")
	if err := os.MkdirAll(filepath.Join(nestedRoot, "etc"), 0o755); err != nil {
		t.Fatalf("mkdir etc: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(nestedRoot, "bin"), 0o755); err != nil {
		t.Fatalf("mkdir bin: %v", err)
	}
	if err := os.WriteFile(filepath.Join(nestedRoot, "etc", "fstab"), []byte(""), 0o644); err != nil {
		t.Fatalf("write fstab: %v", err)
	}

	detector := filesystem.NewDetector(nil)
	mounts, err := detector.Detect(context.Background(), root)
	if err != nil {
		t.Fatalf("detect: %v", err)
	}

	var found bool
	for _, mnt := range mounts {
		if strings.HasSuffix(mnt.ImagePath, "rootfs") && mnt.Type == "directory" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected nested root directory mount in %#v", mounts)
	}
}

func TestFilesystemDetectorDetectsMTDStrings(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	img := filepath.Join(root, "flash.bin")
	data := []byte("bootloader\nmtdparts=flash:512k@0(boot);1536k@0x80000(rootfs)")
	if err := os.WriteFile(img, data, 0o644); err != nil {
		t.Fatalf("write flash: %v", err)
	}

	detector := filesystem.NewDetector(nil)
	mounts, err := detector.Detect(context.Background(), root)
	if err != nil {
		t.Fatalf("detect: %v", err)
	}

	var found bool
	for _, mnt := range mounts {
		if mnt.Type == "mtd" && strings.HasSuffix(mnt.ImagePath, "flash.bin") {
			if !strings.Contains(mnt.Notes, "mtdparts") {
				t.Fatalf("expected mtd notes, got %s", mnt.Notes)
			}
			found = true
		}
	}
	if !found {
		t.Fatalf("expected mtd detection in %#v", mounts)
	}
}
