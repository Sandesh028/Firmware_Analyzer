package secrets

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"

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
	allowList   map[string]struct{}
	patterns    []pattern
	minEntropy  float64
	maxFileSize int64
}

type pattern struct {
	name string
	re   *regexp.Regexp
}

// NewScanner creates a scanner configured with sensible defaults.
func NewScanner(logger *log.Logger, allowList []string) *Scanner {
	if logger == nil {
		logger = log.New(io.Discard, "secrets", log.LstdFlags)
	}
	allow := make(map[string]struct{}, len(allowList))
	for _, item := range allowList {
		allow[item] = struct{}{}
	}
	patterns := []pattern{
		{name: "AWS Access Key", re: regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
		{name: "Generic API Key", re: regexp.MustCompile(`[A-Za-z0-9_]{20,}`)},
		{name: "Private Key", re: regexp.MustCompile(`-----BEGIN [A-Z ]+PRIVATE KEY-----`)},
		{name: "Password Assignment", re: regexp.MustCompile(`(?i)(password|passwd|secret)\s*=\s*['\"]?([^'\"\s]+)`)},
	}
	return &Scanner{
		logger:      logger,
		allowList:   allow,
		patterns:    patterns,
		minEntropy:  3.5,
		maxFileSize: 1 << 20,
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

	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var findings []Finding
	scanner := bufio.NewScanner(file)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		for _, pat := range s.patterns {
			matches := pat.re.FindAllStringSubmatch(line, -1)
			if len(matches) == 0 {
				continue
			}
			for _, match := range matches {
				candidate := match[0]
				if _, ok := s.allowList[candidate]; ok {
					continue
				}
				entropy := utils.ShannonEntropy(candidate)
				if utils.ContainsCredentialKeyword(line) || entropy >= s.minEntropy {
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
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return findings, nil
}
