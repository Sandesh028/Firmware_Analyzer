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

func TestVulnerabilityEnrichmentUsesEmbeddedDatabase(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	binPath := filepath.Join(tmp, "busybox.bin")
	if err := os.WriteFile(binPath, []byte("firmware"), 0o644); err != nil {
		t.Fatalf("write binary: %v", err)
	}

	enricher := vuln.NewEnricher(nil, vuln.Options{})
	findings, err := enricher.Enrich(context.Background(), []binaryinspector.Result{{Path: binPath}})
	if err != nil {
		t.Fatalf("enrich: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected one finding, got %d", len(findings))
	}
	if len(findings[0].CVEs) == 0 {
		t.Fatalf("expected embedded database to provide CVE matches")
	}
}

func TestMergeNormalisesAndDeduplicates(t *testing.T) {
	t.Parallel()

	db1 := map[string][]vuln.CVE{
		"SHA256:c3BF47EA1F4A4A605470313CACB3A44F4A461F68C6FAEAB07E737610CB5AC835": {
			{ID: "CVE-2024-0001", Severity: "medium", References: []string{"https://example.com/a"}},
		},
	}
	db2 := map[string][]vuln.CVE{
		"c3bf47ea1f4a4a605470313cacb3a44f4a461f68c6faeab07e737610cb5ac835": {
			{ID: "CVE-2024-0001", Severity: "high", References: []string{"https://example.com/a", "https://example.com/b"}},
			{ID: "CVE-2020-10135", Severity: "low"},
		},
	}

	merged := vuln.Merge(db1, db2)
	if len(merged) != 1 {
		t.Fatalf("expected one hash, got %d", len(merged))
	}
	list := merged["c3bf47ea1f4a4a605470313cacb3a44f4a461f68c6faeab07e737610cb5ac835"]
	if len(list) != 2 {
		t.Fatalf("expected two CVEs after merge, got %d", len(list))
	}

	var cve0001 vuln.CVE
	for _, c := range list {
		if c.ID == "CVE-2024-0001" {
			cve0001 = c
		}
	}
	if cve0001.Severity != "high" {
		t.Fatalf("expected severity to prefer higher rank, got %q", cve0001.Severity)
	}
	if len(cve0001.References) != 2 {
		t.Fatalf("expected deduplicated references, got %v", cve0001.References)
	}
}
