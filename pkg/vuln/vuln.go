package vuln

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"firmwareanalyzer/pkg/binaryinspector"
)

// CVE represents a single vulnerability entry associated with a binary hash.
type CVE struct {
	ID          string   `json:"id"`
	Severity    string   `json:"severity,omitempty"`
	Description string   `json:"description,omitempty"`
	References  []string `json:"references,omitempty"`
}

type httpDoer interface {
	Do(*http.Request) (*http.Response, error)
}

// OnlineOptions describe an external vulnerability provider.
type OnlineOptions struct {
	Enabled  bool
	Endpoint string
	APIKey   string
}

type cacheEntry struct {
	CVEs []CVE `json:"cves"`
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
	// DisableEmbedded prevents use of the curated database bundled with the
	// binary via go:embed. The embedded database is enabled by default.
	DisableEmbedded bool
	// CacheDir stores online lookup results on disk when provided.
	CacheDir string
	// RateLimitPerMinute bounds external API requests. Values <= 0 disable
	// rate limiting.
	RateLimitPerMinute int
	// HTTPClient allows tests to provide a custom client.
	HTTPClient httpDoer
	// OSV configures optional OSV lookups.
	OSV OnlineOptions
	// NVD configures optional NVD lookups.
	NVD OnlineOptions
}

// Enricher augments binary inspection results with CVE metadata sourced from
// offline databases. Databases are expected to be JSON documents mapping
// hexadecimal SHA-256 digests to arrays of CVE descriptors.
type Enricher struct {
	logger       *log.Logger
	opts         Options
	client       httpDoer
	cache        map[string]cacheEntry
	cacheDir     string
	rateInterval time.Duration
	lastRequest  time.Time
	disableOSV   bool
	disableNVD   bool
}

// NewEnricher builds an Enricher. When logger is nil log output is discarded.
func NewEnricher(logger *log.Logger, opts Options) *Enricher {
	if logger == nil {
		logger = log.New(io.Discard, "vuln", log.LstdFlags)
	}
	e := &Enricher{logger: logger, opts: opts, cache: make(map[string]cacheEntry)}
	if opts.HTTPClient != nil {
		e.client = opts.HTTPClient
	} else {
		e.client = http.DefaultClient
	}
	e.cacheDir = strings.TrimSpace(opts.CacheDir)
	if opts.RateLimitPerMinute > 0 {
		interval := time.Minute / time.Duration(opts.RateLimitPerMinute)
		if interval > 0 {
			e.rateInterval = interval
		}
	}
	if e.opts.OSV.Endpoint == "" {
		e.opts.OSV.Endpoint = "https://api.osv.dev/v1/query"
	}
	if e.opts.NVD.Endpoint == "" {
		e.opts.NVD.Endpoint = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	}
	return e
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
		if e.onlineEnabled() {
			online, lookupErr := e.lookupOnline(ctx, hash)
			if lookupErr != nil {
				e.logger.Printf("online lookup %s: %v", hash, lookupErr)
			}
			if len(online) > 0 {
				finding.CVEs = mergeCVEs(finding.CVEs, online)
			}
		}
		findings = append(findings, finding)
	}
	return findings, nil
}

func (e *Enricher) loadDatabases() (map[string][]CVE, error) {
	var sources []map[string][]CVE

	if !e.opts.DisableEmbedded && len(embeddedCuratedDatabase) > 0 {
		entries, err := ParseDatabase(embeddedCuratedDatabase)
		if err != nil {
			return nil, fmt.Errorf("parse embedded database: %w", err)
		}
		sources = append(sources, entries)
	}

	for _, path := range e.opts.DatabasePaths {
		if strings.TrimSpace(path) == "" {
			continue
		}
		path = filepath.Clean(path)
		data, err := os.ReadFile(path)
		if err != nil {
			if os.IsNotExist(err) {
				e.logger.Printf("skip vulnerability database %s: %v", path, err)
				continue
			}
			e.logger.Printf("skip vulnerability database %s: %v", path, err)
			continue
		}
		entries, err := ParseDatabase(data)
		if err != nil {
			e.logger.Printf("skip vulnerability database %s: %v", path, err)
			continue
		}
		sources = append(sources, entries)
	}

	if len(sources) == 0 && (e.opts.DisableEmbedded || len(embeddedCuratedDatabase) == 0) {
		return make(map[string][]CVE), nil
	}
	return Merge(sources...), nil
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

// ParseDatabase decodes vulnerability data encoded either as a direct map of
// hashes to CVE slices or as an artifacts array. Hashes are normalised to
// lowercase hexadecimal strings without algorithm prefixes.
func ParseDatabase(data []byte) (map[string][]CVE, error) {
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

// Merge combines one or more vulnerability databases into a single map keyed
// by SHA-256 hash. CVE entries are deduplicated by ID, metadata is merged, and
// references are normalised.
func Merge(databases ...map[string][]CVE) map[string][]CVE {
	combined := make(map[string][]CVE)
	for _, db := range databases {
		if db == nil {
			continue
		}
		for hash, cves := range db {
			normalized := normalizeHash(hash)
			if normalized == "" {
				continue
			}
			combined[normalized] = mergeCVEs(combined[normalized], cves)
		}
	}
	return combined
}

func mergeCVEs(existing []CVE, incoming []CVE) []CVE {
	if len(incoming) == 0 {
		return existing
	}

	seen := make(map[string]int, len(existing))
	for i, c := range existing {
		key := strings.ToLower(strings.TrimSpace(c.ID))
		if key == "" {
			continue
		}
		dedupeReferences(&existing[i])
		seen[key] = i
	}

	for _, c := range incoming {
		key := strings.ToLower(strings.TrimSpace(c.ID))
		if key == "" {
			continue
		}
		dedupeReferences(&c)
		if idx, ok := seen[key]; ok {
			existing[idx] = mergeCVE(existing[idx], c)
		} else {
			seen[key] = len(existing)
			existing = append(existing, c)
		}
	}

	sort.Slice(existing, func(i, j int) bool {
		return strings.ToLower(existing[i].ID) < strings.ToLower(existing[j].ID)
	})
	for i := range existing {
		dedupeReferences(&existing[i])
	}
	return existing
}

func mergeCVE(base CVE, update CVE) CVE {
	result := base
	if result.ID == "" {
		result.ID = update.ID
	}

	result.Severity = pickSeverity(result.Severity, update.Severity)

	if result.Description == "" {
		result.Description = update.Description
	}

	result.References = mergeReferences(result.References, update.References)
	return result
}

func pickSeverity(current, candidate string) string {
	current = strings.ToLower(strings.TrimSpace(current))
	candidate = strings.ToLower(strings.TrimSpace(candidate))
	ranks := map[string]int{"critical": 4, "high": 3, "medium": 2, "moderate": 2, "low": 1, "info": 0, "informational": 0}
	if ranks[candidate] > ranks[current] {
		return candidate
	}
	return current
}

func mergeReferences(existing, incoming []string) []string {
	refs := make([]string, 0, len(existing)+len(incoming))
	seen := make(map[string]struct{}, len(existing)+len(incoming))
	for _, r := range existing {
		r = strings.TrimSpace(r)
		if r == "" {
			continue
		}
		key := strings.ToLower(r)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		refs = append(refs, r)
	}
	for _, r := range incoming {
		r = strings.TrimSpace(r)
		if r == "" {
			continue
		}
		key := strings.ToLower(r)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		refs = append(refs, r)
	}
	sort.Strings(refs)
	return refs
}

func dedupeReferences(c *CVE) {
	c.References = mergeReferences(nil, c.References)
}

func (e *Enricher) onlineEnabled() bool {
	return (e.opts.OSV.Enabled && !e.disableOSV) || (e.opts.NVD.Enabled && !e.disableNVD)
}

func (e *Enricher) lookupOnline(ctx context.Context, hash string) ([]CVE, error) {
	if entry, ok := e.fromCache(hash); ok {
		return entry.CVEs, nil
	}
	var combined []CVE
	var errs []string
	if e.opts.OSV.Enabled && !e.disableOSV {
		cves, err := e.queryOSV(ctx, hash)
		if err != nil {
			if e.disableOnPermanentError("osv", err) {
				errs = append(errs, fmt.Sprintf("osv disabled: %v", err))
			} else {
				errs = append(errs, fmt.Sprintf("osv: %v", err))
			}
		} else if len(cves) > 0 {
			combined = mergeCVEs(combined, cves)
		}
	}
	if e.opts.NVD.Enabled && !e.disableNVD {
		cves, err := e.queryNVD(ctx, hash)
		if err != nil {
			if e.disableOnPermanentError("nvd", err) {
				errs = append(errs, fmt.Sprintf("nvd disabled: %v", err))
			} else {
				errs = append(errs, fmt.Sprintf("nvd: %v", err))
			}
		} else if len(cves) > 0 {
			combined = mergeCVEs(combined, cves)
		}
	}
	e.storeCache(hash, combined)
	if len(errs) > 0 && len(combined) == 0 {
		return combined, errors.New(strings.Join(errs, "; "))
	}
	return combined, nil
}

func (e *Enricher) fromCache(hash string) (cacheEntry, bool) {
	if entry, ok := e.cache[hash]; ok {
		return entry, true
	}
	if e.cacheDir == "" {
		return cacheEntry{}, false
	}
	path := e.cacheFile(hash)
	data, err := os.ReadFile(path)
	if err != nil {
		return cacheEntry{}, false
	}
	var entry cacheEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return cacheEntry{}, false
	}
	e.cache[hash] = entry
	return entry, true
}

func (e *Enricher) storeCache(hash string, cves []CVE) {
	entry := cacheEntry{CVEs: cves}
	e.cache[hash] = entry
	if e.cacheDir == "" {
		return
	}
	data, err := json.Marshal(entry)
	if err != nil {
		return
	}
	if err := os.MkdirAll(e.cacheDir, 0o755); err != nil {
		return
	}
	_ = os.WriteFile(e.cacheFile(hash), data, 0o644)
}

func (e *Enricher) cacheFile(hash string) string {
	return filepath.Join(e.cacheDir, fmt.Sprintf("%s.json", hash))
}

func (e *Enricher) throttle(ctx context.Context) error {
	if e.rateInterval <= 0 {
		return nil
	}
	wait := e.rateInterval - time.Since(e.lastRequest)
	if wait > 0 {
		timer := time.NewTimer(wait)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
		}
	}
	e.lastRequest = time.Now()
	return nil
}

func (e *Enricher) queryOSV(ctx context.Context, hash string) ([]CVE, error) {
	if err := e.throttle(ctx); err != nil {
		return nil, err
	}
	payload := map[string]string{"hash": "sha256:" + hash}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.opts.OSV.Endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := e.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, &providerError{provider: "osv", status: resp.StatusCode, message: fmt.Sprintf("http %s", resp.Status)}
	}
	var parsed struct {
		Vulns []struct {
			ID       string `json:"id"`
			Summary  string `json:"summary"`
			Details  string `json:"details"`
			Severity []struct {
				Type  string `json:"type"`
				Score string `json:"score"`
			} `json:"severity"`
			References []struct {
				URL string `json:"url"`
			} `json:"references"`
		} `json:"vulns"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, err
	}
	var out []CVE
	for _, vuln := range parsed.Vulns {
		cve := CVE{ID: vuln.ID}
		if cve.Description == "" {
			cve.Description = strings.TrimSpace(vuln.Summary)
		}
		if cve.Description == "" {
			cve.Description = strings.TrimSpace(vuln.Details)
		}
		cve.Severity = pickOSVSeverity(vuln.Severity)
		for _, ref := range vuln.References {
			if ref.URL != "" {
				cve.References = append(cve.References, ref.URL)
			}
		}
		out = append(out, cve)
	}
	return out, nil
}

func (e *Enricher) queryNVD(ctx context.Context, hash string) ([]CVE, error) {
	if err := e.throttle(ctx); err != nil {
		return nil, err
	}
	endpoint, err := url.Parse(e.opts.NVD.Endpoint)
	if err != nil {
		return nil, err
	}
	q := endpoint.Query()
	q.Set("sha256", hash)
	endpoint.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(e.opts.NVD.APIKey) != "" {
		req.Header.Set("X-Api-Key", strings.TrimSpace(e.opts.NVD.APIKey))
	}
	resp, err := e.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, &providerError{provider: "nvd", status: resp.StatusCode, message: fmt.Sprintf("http %s", resp.Status)}
	}
	var parsed struct {
		Vulnerabilities []struct {
			Cve struct {
				ID           string `json:"id"`
				Descriptions []struct {
					Value string `json:"value"`
				} `json:"descriptions"`
				Metrics struct {
					CvssMetricV31 []struct {
						CvssData struct {
							BaseSeverity string `json:"baseSeverity"`
						} `json:"cvssData"`
					} `json:"cvssMetricV31"`
					CvssMetricV30 []struct {
						CvssData struct {
							BaseSeverity string `json:"baseSeverity"`
						} `json:"cvssData"`
					} `json:"cvssMetricV30"`
					CvssMetricV2 []struct {
						BaseSeverity string `json:"baseSeverity"`
					} `json:"cvssMetricV2"`
				} `json:"metrics"`
				References struct {
					ReferenceData []struct {
						URL string `json:"url"`
					} `json:"referenceData"`
				} `json:"references"`
			} `json:"cve"`
		} `json:"vulnerabilities"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, err
	}
	var out []CVE
	for _, entry := range parsed.Vulnerabilities {
		cveData := entry.Cve
		cve := CVE{ID: cveData.ID, Severity: pickNVDSeverity(cveData.Metrics)}
		for _, desc := range cveData.Descriptions {
			if strings.TrimSpace(desc.Value) != "" {
				cve.Description = strings.TrimSpace(desc.Value)
				break
			}
		}
		for _, ref := range cveData.References.ReferenceData {
			if ref.URL != "" {
				cve.References = append(cve.References, ref.URL)
			}
		}
		out = append(out, cve)
	}
	return out, nil
}

type providerError struct {
	provider string
	status   int
	message  string
}

func (e *providerError) Error() string {
	return e.message
}

func (e *providerError) Permanent() bool {
	if e.status == http.StatusTooManyRequests {
		return false
	}
	return e.status >= 400 && e.status < 500
}

func (e *providerError) Provider() string {
	return e.provider
}

func (en *Enricher) disableOnPermanentError(provider string, err error) bool {
	var perr *providerError
	if !errors.As(err, &perr) || !perr.Permanent() {
		return false
	}
	en.disableProvider(provider, perr)
	return true
}

func (en *Enricher) disableProvider(provider string, err *providerError) {
	switch provider {
	case "osv":
		if en.disableOSV {
			return
		}
		en.disableOSV = true
	case "nvd":
		if en.disableNVD {
			return
		}
		en.disableNVD = true
	default:
		return
	}
	en.logger.Printf("disable %s lookups after %s", provider, err.message)
}

func pickOSVSeverity(entries []struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}) string {
	for _, entry := range entries {
		if entry.Score != "" {
			return strings.ToLower(entry.Score)
		}
		if entry.Type != "" {
			return strings.ToLower(entry.Type)
		}
	}
	return ""
}

func pickNVDSeverity(metrics struct {
	CvssMetricV31 []struct {
		CvssData struct {
			BaseSeverity string `json:"baseSeverity"`
		} `json:"cvssData"`
	} `json:"cvssMetricV31"`
	CvssMetricV30 []struct {
		CvssData struct {
			BaseSeverity string `json:"baseSeverity"`
		} `json:"cvssData"`
	} `json:"cvssMetricV30"`
	CvssMetricV2 []struct {
		BaseSeverity string `json:"baseSeverity"`
	} `json:"cvssMetricV2"`
}) string {
	severityOrder := []string{
		firstNVDSeverity(metrics.CvssMetricV31),
		firstNVDSeverity(metrics.CvssMetricV30),
	}
	for _, sev := range severityOrder {
		if sev != "" {
			return strings.ToLower(sev)
		}
	}
	if len(metrics.CvssMetricV2) > 0 {
		return strings.ToLower(metrics.CvssMetricV2[0].BaseSeverity)
	}
	return ""
}

func firstNVDSeverity(metrics []struct {
	CvssData struct {
		BaseSeverity string `json:"baseSeverity"`
	} `json:"cvssData"`
}) string {
	for _, metric := range metrics {
		if metric.CvssData.BaseSeverity != "" {
			return metric.CvssData.BaseSeverity
		}
	}
	return ""
}
