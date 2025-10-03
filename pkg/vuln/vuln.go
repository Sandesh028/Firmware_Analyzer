package vuln

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"

	"firmwareanalyzer/pkg/binaryinspector"
)

// CVE represents a single vulnerability entry associated with a binary hash.
type CVE struct {
	ID          string   `json:"id"`
	Severity    string   `json:"severity,omitempty"`
	Description string   `json:"description,omitempty"`
	References  []string `json:"references,omitempty"`
}

// Finding links a binary to zero or more CVEs discovered during enrichment.
type Finding struct {
	Path  string `json:"path"`
	Hash  string `json:"hash"`
	CVEs  []CVE  `json:"cves,omitempty"`
	Error string `json:"error,omitempty"`
}

// Options configure the enrichment behaviour.
type Options struct {
	// DatabasePaths points to JSON files containing hash -> CVE mappings.
	DatabasePaths []string
}

// Enricher augments binary inspection results with CVE metadata sourced from
// offline databases. Databases are expected to be JSON documents mapping
// hexadecimal SHA-256 digests to arrays of CVE descriptors.
type Enricher struct {
	logger *log.Logger
	opts   Options
}

// NewEnricher builds an Enricher. When logger is nil log output is discarded.
func NewEnricher(logger *log.Logger, opts Options) *Enricher {
	if logger == nil {
		logger = log.New(io.Discard, "vuln", log.LstdFlags)
	}
	return &Enricher{logger: logger, opts: opts}
}

// Enrich calculates hashes for the supplied binaries and looks them up in the
// configured CVE databases. It returns a slice of findings, preserving the
// order of the input binaries. Errors hashing individual binaries are captured
// within the Finding so that other binaries can still be processed.
func (e *Enricher) Enrich(ctx context.Context, binaries []binaryinspector.Result) ([]Finding, error) {
	db, err := e.loadDatabases()
	if err != nil {
		return nil, err
	}

	findings := make([]Finding, 0, len(binaries))
	for _, bin := range binaries {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		finding := Finding{Path: bin.Path}
		if bin.Err != "" {
			finding.Error = bin.Err
			findings = append(findings, finding)
			continue
		}

		hash, err := hashFile(bin.Path)
		if err != nil {
			finding.Error = err.Error()
			findings = append(findings, finding)
			continue
		}
		finding.Hash = hash
		finding.CVEs = db[hash]
		findings = append(findings, finding)
	}
	return findings, nil
}

func (e *Enricher) loadDatabases() (map[string][]CVE, error) {
	combined := make(map[string][]CVE)
	for _, path := range e.opts.DatabasePaths {
		if strings.TrimSpace(path) == "" {
			continue
		}
		path = filepath.Clean(path)
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read database %s: %w", path, err)
		}
		entries, err := parseDatabase(data)
		if err != nil {
			return nil, fmt.Errorf("parse database %s: %w", path, err)
		}
		for hash, cves := range entries {
			if len(hash) == 0 {
				continue
			}
			normalized := normalizeHash(hash)
			combined[normalized] = append(combined[normalized], cves...)
		}
	}
	return combined, nil
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open binary: %w", err)
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("hash binary: %w", err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func parseDatabase(data []byte) (map[string][]CVE, error) {
	// Support the "artifacts" structured representation used by some feeds.
	var wrapper struct {
		Artifacts []struct {
			SHA256 string `json:"sha256"`
			CVEs   []CVE  `json:"cves"`
		} `json:"artifacts"`
	}
	if err := json.Unmarshal(data, &wrapper); err == nil && len(wrapper.Artifacts) > 0 {
		out := make(map[string][]CVE)
		for _, art := range wrapper.Artifacts {
			if art.SHA256 == "" {
				continue
			}
			out[normalizeHash(art.SHA256)] = append(out[normalizeHash(art.SHA256)], art.CVEs...)
		}
		return out, nil
	}

	// Fall back to simple hash -> []CVE maps.
	var direct map[string][]CVE
	if err := json.Unmarshal(data, &direct); err == nil {
		if direct == nil {
			direct = make(map[string][]CVE)
		}
		return direct, nil
	}
	return nil, errors.New("unrecognised database format")
}

func normalizeHash(value string) string {
	cleaned := strings.TrimSpace(strings.ToLower(value))
	if strings.HasPrefix(cleaned, "sha256:") {
		cleaned = strings.TrimPrefix(cleaned, "sha256:")
	}
	return cleaned
}
