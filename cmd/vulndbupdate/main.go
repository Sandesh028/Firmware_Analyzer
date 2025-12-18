package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"firmwareanalyzer/pkg/vuln"
)

type sourceList []string

func (s *sourceList) String() string {
	return strings.Join(*s, ",")
}

func (s *sourceList) Set(value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return errors.New("empty source value")
	}
	*s = append(*s, value)
	return nil
}

func main() {
	var sources sourceList
	flag.Var(&sources, "source", "path or URL for a vulnerability feed (repeatable)")
	output := flag.String("out", "pkg/vuln/data/curated.json", "path to write the merged database")
	allowInsecure := flag.Bool("insecure-http", false, "allow plain HTTP downloads for feeds")
	flag.Parse()

	if len(sources) == 0 {
		log.Fatal("at least one --source must be provided")
	}

	var databases []map[string][]vuln.CVE
	for _, src := range sources {
		data, err := loadSource(src, *allowInsecure)
		if err != nil {
			log.Fatalf("load source %s: %v", src, err)
		}
		entries, err := vuln.ParseDatabase(data)
		if err != nil {
			log.Fatalf("parse source %s: %v", src, err)
		}
		databases = append(databases, entries)
	}

	merged := vuln.Merge(databases...)
	if len(merged) == 0 {
		log.Fatal("merged database is empty")
	}

	if err := writeDatabase(*output, sources, merged); err != nil {
		log.Fatalf("write database: %v", err)
	}
	log.Printf("database written to %s (%d artifacts)", *output, len(merged))
}

func loadSource(source string, allowInsecure bool) ([]byte, error) {
	if strings.HasPrefix(source, "http://") || strings.HasPrefix(source, "https://") {
		if strings.HasPrefix(source, "http://") && !allowInsecure {
			return nil, fmt.Errorf("insecure http source blocked: %s", source)
		}
		req, err := http.NewRequest(http.MethodGet, source, nil)
		if err != nil {
			return nil, err
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("unexpected status %d", resp.StatusCode)
		}
		return io.ReadAll(resp.Body)
	}
	return os.ReadFile(source)
}

func writeDatabase(path string, sources []string, db map[string][]vuln.CVE) error {
	type artifact struct {
		SHA256 string     `json:"sha256"`
		CVEs   []vuln.CVE `json:"cves"`
	}
	type payload struct {
		Generated string     `json:"generated"`
		Sources   []string   `json:"sources"`
		Artifacts []artifact `json:"artifacts"`
	}

	hashes := make([]string, 0, len(db))
	for hash := range db {
		hashes = append(hashes, hash)
	}
	sort.Strings(hashes)

	artifacts := make([]artifact, 0, len(hashes))
	for _, hash := range hashes {
		cves := append([]vuln.CVE(nil), db[hash]...)
		sort.Slice(cves, func(i, j int) bool {
			return strings.ToLower(cves[i].ID) < strings.ToLower(cves[j].ID)
		})
		artifacts = append(artifacts, artifact{SHA256: hash, CVEs: cves})
	}

	body := payload{
		Generated: time.Now().UTC().Format(time.RFC3339),
		Sources:   append([]string(nil), sources...),
		Artifacts: artifacts,
	}

	data, err := json.MarshalIndent(body, "", "  ")
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}

	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}
