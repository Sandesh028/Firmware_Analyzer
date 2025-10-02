package tests

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"firmwareanalyzer/pkg/binaryinspector"
	"firmwareanalyzer/pkg/vuln"
)

func TestVulnerabilityEnrichmentMatchesDatabase(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	binPath := filepath.Join(tmp, "app.bin")
	if err := os.WriteFile(binPath, []byte("firmware"), 0o644); err != nil {
		t.Fatalf("write binary: %v", err)
	}
	sum := sha256.Sum256([]byte("firmware"))
	hash := hex.EncodeToString(sum[:])

	dbPath := filepath.Join(tmp, "db.json")
	dbContent := "{\n  \"" + hash + "\": [{\n    \"id\": \"CVE-2024-0001\",\n    \"severity\": \"high\"\n  }]\n}"
	if err := os.WriteFile(dbPath, []byte(dbContent), 0o644); err != nil {
		t.Fatalf("write db: %v", err)
	}

	enricher := vuln.NewEnricher(nil, vuln.Options{DatabasePaths: []string{dbPath}})
	findings, err := enricher.Enrich(context.Background(), []binaryinspector.Result{{Path: binPath}})
	if err != nil {
		t.Fatalf("enrich: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected one finding, got %d", len(findings))
	}
	if findings[0].Hash != hash {
		t.Fatalf("unexpected hash %s", findings[0].Hash)
	}
	if len(findings[0].CVEs) != 1 || findings[0].CVEs[0].ID != "CVE-2024-0001" {
		t.Fatalf("missing CVE match: %#v", findings[0].CVEs)
	}
}

func TestVulnerabilityEnrichmentCapturesErrors(t *testing.T) {
	t.Parallel()

	enricher := vuln.NewEnricher(nil, vuln.Options{})
	findings, err := enricher.Enrich(context.Background(), []binaryinspector.Result{{Path: "does-not-exist"}})
	if err != nil {
		t.Fatalf("enrich: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected one finding, got %d", len(findings))
	}
	if findings[0].Error == "" {
		t.Fatalf("expected error message when hashing fails")
	}
}
