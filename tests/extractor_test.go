package tests

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"os"
	"path/filepath"
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
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("close gzip: %v", err)
	}
	if err := os.WriteFile(firmwarePath, buf.Bytes(), 0o644); err != nil {
		t.Fatalf("write firmware: %v", err)
	}

	ext := extractor.New(extractor.Options{}, nil)
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
}
