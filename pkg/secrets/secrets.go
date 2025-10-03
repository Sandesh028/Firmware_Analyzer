package secrets

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"firmwareanalyzer/pkg/utils"
)

// Finding represents a potential secret discovered within a file.
type Finding struct {
	File    string  `json:"file"`
	Line    int     `json:"line"`
	Match   string  `json:"match"`
	Rule    string  `json:"rule"`
	Entropy float64 `json:"entropy"`
}

// Scanner searches firmware trees for credentials using regex and entropy
// heuristics. An allow-list can be provided to reduce false positives.
type Scanner struct {
	logger      *log.Logger
	allowExact  map[string]struct{}
	allowRules  map[string][]string
	patterns    []pattern
	minEntropy  float64
	maxFileSize int64
}

type pattern struct {
	name       string
	re         *regexp.Regexp
	minEntropy float64
	minLength  int
}

// ScannerOptions customise the behaviour of the secret scanner.
type ScannerOptions struct {
	AllowExact        []string
	AllowRulePatterns map[string][]string
	MinEntropy        float64
	MaxFileSize       int64
}

// NewScanner creates a scanner configured with sensible defaults.
func NewScanner(logger *log.Logger, allowList []string) *Scanner {
	return NewScannerWithOptions(logger, ScannerOptions{AllowExact: allowList})
}

// NewScannerWithOptions builds a scanner using custom thresholds and allow-lists.
func NewScannerWithOptions(logger *log.Logger, opts ScannerOptions) *Scanner {
	if logger == nil {
		logger = log.New(io.Discard, "secrets", log.LstdFlags)
	}
	allowExact := make(map[string]struct{}, len(opts.AllowExact))
	for _, item := range opts.AllowExact {
		allowExact[item] = struct{}{}
	}
	patterns := []pattern{
		{name: "AWS Access Key", re: regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
		{name: "Generic API Key", re: regexp.MustCompile(`[A-Za-z0-9_\-]{24,}`), minEntropy: 3.5, minLength: 24},
		{name: "JWT", re: regexp.MustCompile(`eyJ[\w-]{20,}\.[\w-]{20,}\.[\w-]{10,}`), minEntropy: 3.0},
		{name: "Slack Token", re: regexp.MustCompile(`xox[baprs]-[A-Za-z0-9-]{10,}`), minEntropy: 3.0},
		{name: "Private Key", re: regexp.MustCompile(`-----BEGIN [A-Z ]+PRIVATE KEY-----`), minEntropy: 0, minLength: 0},
		{name: "SSH Authorized Key", re: regexp.MustCompile(`ssh-(rsa|ed25519|dss) [A-Za-z0-9+/=]+`), minEntropy: 2.5},
		{name: "Password Assignment", re: regexp.MustCompile(`(?i)(password|passwd|secret)\s*=\s*['\"]?([^'\"\s]+)`), minEntropy: 0},
	}
	minEntropy := opts.MinEntropy
	if minEntropy == 0 {
		minEntropy = 3.5
	}
	maxFile := opts.MaxFileSize
	if maxFile == 0 {
		maxFile = 1 << 20
	}
	return &Scanner{
		logger:      logger,
		allowExact:  allowExact,
		allowRules:  opts.AllowRulePatterns,
		patterns:    patterns,
		minEntropy:  minEntropy,
		maxFileSize: maxFile,
	}
}

// Scan walks the root directory, scanning text files and reporting any
// discoveries that meet entropy requirements and are not allow-listed.
func (s *Scanner) Scan(ctx context.Context, root string) ([]Finding, error) {
	var findings []Finding
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if info.Size() > s.maxFileSize {
			return nil
		}
		fileFindings, err := s.scanFile(path)
		if err != nil {
			return err
		}
		findings = append(findings, fileFindings...)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].File == findings[j].File {
			return findings[i].Line < findings[j].Line
		}
		return findings[i].File < findings[j].File
	})
	return findings, nil
}

func (s *Scanner) scanFile(path string) ([]Finding, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}
	if !utils.LooksLikeText(data) {
		return nil, nil
	}

	var findings []Finding
	lines := bytes.Split(data, []byte{'\n'})
	for i, rawLine := range lines {
		lineNum := i + 1
		line := strings.TrimRight(string(rawLine), "\r")
		for _, pat := range s.patterns {
			matches := pat.re.FindAllStringSubmatch(line, -1)
			if len(matches) == 0 {
				continue
			}
			for _, match := range matches {
				candidate := match[0]
				if _, ok := s.allowExact[candidate]; ok {
					continue
				}
				if s.isRuleSuppressed(pat.name, candidate) {
					continue
				}
				entropy := utils.ShannonEntropy(candidate)
				threshold := s.minEntropy
				if pat.minEntropy > 0 {
					threshold = pat.minEntropy
				}
				if pat.minLength > 0 && len(candidate) < pat.minLength {
					continue
				}
				if utils.ContainsCredentialKeyword(line) || entropy >= threshold {
					findings = append(findings, Finding{
						File:    path,
						Line:    lineNum,
						Match:   candidate,
						Rule:    pat.name,
						Entropy: entropy,
					})
				}
			}
		}
	}
	return findings, nil
}

func (s *Scanner) isRuleSuppressed(rule, candidate string) bool {
	if len(s.allowRules) == 0 {
		return false
	}
	patterns, ok := s.allowRules[rule]
	if !ok {
		return false
	}
	for _, pattern := range patterns {
		if ok, _ := filepath.Match(pattern, candidate); ok {
			return true
		}
		if strings.HasPrefix(candidate, pattern) {
			return true
		}
	}
	return false
}
