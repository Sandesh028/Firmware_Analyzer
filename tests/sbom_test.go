package tests

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
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

	gen, err := sbom.NewGenerator(nil, sbom.Options{Formats: []sbom.Format{sbom.FormatSPDXJSON}, ProductName: "test"})
	if err != nil {
		t.Fatalf("new generator: %v", err)
	}
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

	gen, err := sbom.NewGenerator(nil, sbom.Options{Formats: []sbom.Format{sbom.FormatCycloneDX}})
	if err != nil {
		t.Fatalf("new generator: %v", err)
	}
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

	doc := sbom.Document{Format: sbom.FormatSPDXJSON, Name: "test"}
	out := filepath.Join(t.TempDir(), "sbom.json")
	if err := sbom.WriteJSON(doc, out); err != nil {
		t.Fatalf("write json: %v", err)
	}
	if _, err := os.Stat(out); err != nil {
		t.Fatalf("sbom file missing: %v", err)
	}
}

func TestSBOMEncodeTagValueAndSigning(t *testing.T) {
	t.Parallel()

	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	pemData := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})
	keyPath := filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(keyPath, pemData, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	gen, err := sbom.NewGenerator(nil, sbom.Options{Formats: []sbom.Format{sbom.FormatSPDXTagValue}, SigningKeyPath: keyPath})
	if err != nil {
		t.Fatalf("new generator: %v", err)
	}
	doc := sbom.Document{Format: sbom.FormatSPDXTagValue, Name: "firmware"}
	data, ext, err := sbom.Encode(doc, sbom.FormatSPDXTagValue)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if ext != "spdx" {
		t.Fatalf("unexpected extension %s", ext)
	}
	sig, err := gen.Sign(data)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if len(sig) != ed25519.SignatureSize {
		t.Fatalf("unexpected signature length %d", len(sig))
	}
	if len(data) == 0 {
		t.Fatalf("expected tag-value content")
	}
}
