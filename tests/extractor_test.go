package tests

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"firmwareanalyzer/pkg/extractor"
)

func TestExtractorHandlesTarGz(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	firmwarePath := filepath.Join(tmp, "firmware.tgz")

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	contents := map[string]string{
		"etc/config.ini": "user=admin\npassword=secret\n",
		"bin/app":        "#!/bin/sh\necho hi\n",
	}
	for name, data := range contents {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o755, Size: int64(len(data))}); err != nil {
			t.Fatalf("write header: %v", err)
		}
		if _, err := tw.Write([]byte(data)); err != nil {
			t.Fatalf("write data: %v", err)
		}
	}
	squash := append([]byte("hsqs"), bytes.Repeat([]byte{0}, 64)...)
	if err := tw.WriteHeader(&tar.Header{Name: "rootfs.squashfs", Mode: 0o644, Size: int64(len(squash))}); err != nil {
		t.Fatalf("write squash header: %v", err)
	}
	if _, err := tw.Write(squash); err != nil {
		t.Fatalf("write squash data: %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("close gzip: %v", err)
	}
	if err := os.WriteFile(firmwarePath, buf.Bytes(), 0o644); err != nil {
		t.Fatalf("write firmware: %v", err)
	}

	ext := extractor.New(extractor.Options{ExternalExtractors: []string{}}, nil)
	result, err := ext.Extract(context.Background(), firmwarePath)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}

	for name := range contents {
		if _, err := os.Stat(filepath.Join(result.OutputDir, name)); err != nil {
			t.Fatalf("expected extracted file %s: %v", name, err)
		}
	}
	if len(result.Partitions) == 0 {
		t.Fatalf("expected partition metadata, got %#v", result.Partitions)
	}
	var sawSquash bool
	for _, part := range result.Partitions {
		if part.Type == "squashfs" && strings.HasSuffix(part.Path, "rootfs.squashfs") {
			sawSquash = part.Notes != "" && part.Compression != ""
		}
		if part.Type == "directory" && strings.Contains(part.Name, string(os.PathSeparator)) {
			t.Fatalf("unexpected nested directory partition %q", part.Name)
		}
	}
	if !sawSquash {
		t.Fatalf("expected squashfs partition with notes, got %#v", result.Partitions)
	}
}

func TestExtractorNormalizesSingleDirectoryRoot(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	firmwarePath := filepath.Join(tmp, "firmware.tar")

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if err := tw.WriteHeader(&tar.Header{Name: "squashfs-root/", Mode: 0o755, Typeflag: tar.TypeDir}); err != nil {
		t.Fatalf("write dir header: %v", err)
	}
	data := []byte("root:x:0:0:root:/root:/bin/sh\n")
	if err := tw.WriteHeader(&tar.Header{Name: "squashfs-root/etc/passwd", Mode: 0o644, Size: int64(len(data))}); err != nil {
		t.Fatalf("write file header: %v", err)
	}
	if _, err := tw.Write(data); err != nil {
		t.Fatalf("write data: %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	if err := os.WriteFile(firmwarePath, buf.Bytes(), 0o644); err != nil {
		t.Fatalf("write firmware: %v", err)
	}

	ext := extractor.New(extractor.Options{ExternalExtractors: []string{}}, nil)
	result, err := ext.Extract(context.Background(), firmwarePath)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if !strings.HasSuffix(result.OutputDir, "squashfs-root") {
		t.Fatalf("expected normalized root, got %s", result.OutputDir)
	}
}
