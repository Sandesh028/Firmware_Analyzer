package tests

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"firmwareanalyzer/pkg/binaryinspector"
	"firmwareanalyzer/pkg/extractor"
	"firmwareanalyzer/pkg/sbom"
)

func TestSBOMGeneratorReadsOpkgControls(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	controlDir := filepath.Join(root, "usr", "lib", "opkg", "info")
	if err := os.MkdirAll(controlDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	control := "Package: busybox\nVersion: 1.36.0\nMaintainer: OpenWrt\n"
	if err := os.WriteFile(filepath.Join(controlDir, "busybox.control"), []byte(control), 0o644); err != nil {
		t.Fatalf("write control: %v", err)
	}

	gen := sbom.NewGenerator(nil, sbom.Options{Format: sbom.FormatSPDX, ProductName: "test"})
	part := extractor.Partition{Name: "rootfs", Path: root, Type: "directory"}
	doc, err := gen.Generate(context.Background(), root, nil, []extractor.Partition{part})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if len(doc.Packages) != 1 {
		t.Fatalf("expected 1 package, got %d", len(doc.Packages))
	}
	if doc.Packages[0].Name != "busybox" || doc.Packages[0].Version != "1.36.0" {
		t.Fatalf("unexpected package data: %#v", doc.Packages[0])
	}
	if len(doc.Partitions) != 1 || doc.Partitions[0].Name != "rootfs" {
		t.Fatalf("expected partition metadata, got %#v", doc.Partitions)
	}
}

func TestSBOMGeneratorFallsBackToBinaries(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	binPath := filepath.Join(root, "bin", "app")
	if err := os.MkdirAll(filepath.Dir(binPath), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(binPath, []byte("binary"), 0o755); err != nil {
		t.Fatalf("write binary: %v", err)
	}

	gen := sbom.NewGenerator(nil, sbom.Options{Format: sbom.FormatCycloneDX})
	doc, err := gen.Generate(context.Background(), root, []binaryinspector.Result{{Path: binPath}}, nil)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if len(doc.Packages) != 1 || doc.Packages[0].Name != "app" {
		t.Fatalf("expected fallback package, got %#v", doc.Packages)
	}
}

func TestSBOMWriteJSON(t *testing.T) {
	t.Parallel()

	doc := sbom.Document{Format: sbom.FormatSPDX, Name: "test"}
	out := filepath.Join(t.TempDir(), "sbom.json")
	if err := sbom.WriteJSON(doc, out); err != nil {
		t.Fatalf("write json: %v", err)
	}
	if _, err := os.Stat(out); err != nil {
		t.Fatalf("sbom file missing: %v", err)
	}
}
