package tests

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"firmwareanalyzer/pkg/binaryinspector"
	"firmwareanalyzer/pkg/sbom"
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

func TestVulnerabilityEnrichmentSkipsMissingDatabase(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	binPath := filepath.Join(tmp, "firmware.bin")
	if err := os.WriteFile(binPath, []byte("firmware"), 0o644); err != nil {
		t.Fatalf("write binary: %v", err)
	}

	missing := filepath.Join(tmp, "missing.json")
	opts := vuln.Options{DatabasePaths: []string{missing}, DisableEmbedded: true}
	enricher := vuln.NewEnricher(nil, opts)
	if _, err := enricher.Enrich(context.Background(), []binaryinspector.Result{{Path: binPath}}); err != nil {
		t.Fatalf("enrich should skip missing database: %v", err)
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

func TestVulnerabilityOnlineLookupCachesResults(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	binPath := filepath.Join(tmp, "firmware.bin")
	content := []byte("firmware-data")
	if err := os.WriteFile(binPath, content, 0o644); err != nil {
		t.Fatalf("write binary: %v", err)
	}
	sum := sha256.Sum256(content)
	expectedHash := "sha256:" + hex.EncodeToString(sum[:])

	var requests int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requests, 1)
		defer r.Body.Close()
		var payload map[string]string
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if payload["hash"] != expectedHash {
			http.Error(w, "unexpected hash", http.StatusBadRequest)
			return
		}
		resp := map[string]any{
			"vulns": []map[string]any{{
				"id":         "CVE-2024-9999",
				"summary":    "test vulnerability",
				"references": []map[string]string{{"url": "https://example.com"}},
			}},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	opts := vuln.Options{
		DisableEmbedded: true,
		CacheDir:        filepath.Join(tmp, "cache"),
		OSV:             vuln.OnlineOptions{Enabled: true, Endpoint: server.URL},
		HTTPClient:      server.Client(),
	}

	enricher := vuln.NewEnricher(nil, opts)
	findings, err := enricher.Enrich(context.Background(), []binaryinspector.Result{{Path: binPath}})
	if err != nil {
		t.Fatalf("enrich: %v", err)
	}
	if len(findings) != 1 || len(findings[0].CVEs) != 1 {
		t.Fatalf("expected online CVE, got %#v", findings)
	}
	if atomic.LoadInt32(&requests) != 1 {
		t.Fatalf("expected one HTTP request, got %d", requests)
	}

	// Recreate the enricher to ensure disk cache is used instead of hitting the server again.
	enricherCached := vuln.NewEnricher(nil, opts)
	_, err = enricherCached.Enrich(context.Background(), []binaryinspector.Result{{Path: binPath}})
	if err != nil {
		t.Fatalf("enrich (cached): %v", err)
	}
	if atomic.LoadInt32(&requests) != 1 {
		t.Fatalf("expected cached result without extra HTTP calls, got %d", requests)
	}
}

func TestEnrichPackagesUsesOfflineDatabase(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	dbPath := filepath.Join(tmp, "packages.json")
	db := map[string]any{
		"packages": []map[string]any{{
			"name":      "openssl",
			"version":   "1.1.1",
			"ecosystem": "linux",
			"cves": []map[string]any{{
				"id":       "CVE-2024-1234",
				"severity": "high",
			}},
		}},
	}
	data, err := json.Marshal(db)
	if err != nil {
		t.Fatalf("marshal db: %v", err)
	}
	if err := os.WriteFile(dbPath, data, 0o644); err != nil {
		t.Fatalf("write db: %v", err)
	}

	enricher := vuln.NewEnricher(nil, vuln.Options{DatabasePaths: []string{dbPath}, DisableEmbedded: true})
	packages := []sbom.Package{{Name: "openssl", Version: "1.1.1", Supplier: "linux"}}
	findings, err := enricher.EnrichPackages(context.Background(), packages)
	if err != nil {
		t.Fatalf("enrich packages: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected one finding, got %d", len(findings))
	}
	if len(findings[0].CVEs) != 1 || findings[0].CVEs[0].ID != "CVE-2024-1234" {
		t.Fatalf("expected offline CVE match, got %#v", findings[0].CVEs)
	}
}

func TestEnrichPackagesDisablesProviderOnPermanentError(t *testing.T) {
	t.Parallel()

	var requests int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requests, 1)
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	defer server.Close()

	opts := vuln.Options{
		DisableEmbedded: true,
		OSV:             vuln.OnlineOptions{Enabled: true, Endpoint: server.URL},
		HTTPClient:      server.Client(),
	}
	enricher := vuln.NewEnricher(nil, opts)
	packages := []sbom.Package{{Name: "busybox", Version: "1.36.0"}}
	findings, err := enricher.EnrichPackages(context.Background(), packages)
	if err != nil {
		t.Fatalf("enrich packages: %v", err)
	}
	if requests != 1 {
		t.Fatalf("expected a single request before provider disable, got %d", requests)
	}
	if len(findings) != 1 {
		t.Fatalf("expected single finding, got %d", len(findings))
	}
	if len(findings[0].CVEs) != 0 {
		t.Fatalf("expected no CVEs on provider failure, got %#v", findings[0].CVEs)
	}
	if findings[0].Error == "" || !strings.Contains(findings[0].Error, "osv disabled") {
		t.Fatalf("expected disable error, got %#v", findings[0])
	}
}

func TestVulnerabilityOnlineLookupDisablesAfterPermanentError(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	binOne := filepath.Join(tmp, "one.bin")
	if err := os.WriteFile(binOne, []byte("one"), 0o644); err != nil {
		t.Fatalf("write one: %v", err)
	}
	binTwo := filepath.Join(tmp, "two.bin")
	if err := os.WriteFile(binTwo, []byte("two"), 0o644); err != nil {
		t.Fatalf("write two: %v", err)
	}

	var requests int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requests, 1)
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer server.Close()

	opts := vuln.Options{
		DisableEmbedded: true,
		OSV:             vuln.OnlineOptions{Enabled: true, Endpoint: server.URL},
		HTTPClient:      server.Client(),
	}
	enricher := vuln.NewEnricher(nil, opts)
	binaries := []binaryinspector.Result{{Path: binOne}, {Path: binTwo}}

	if _, err := enricher.Enrich(context.Background(), binaries); err != nil {
		t.Fatalf("enrich: %v", err)
	}
	if got := atomic.LoadInt32(&requests); got != 1 {
		t.Fatalf("expected one request before disabling, got %d", got)
	}

	if _, err := enricher.Enrich(context.Background(), binaries); err != nil {
		t.Fatalf("enrich second run: %v", err)
	}
	if got := atomic.LoadInt32(&requests); got != 1 {
		t.Fatalf("expected online provider to remain disabled, got %d requests", got)
	}
}
