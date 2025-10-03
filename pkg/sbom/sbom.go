package sbom

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"firmwareanalyzer/pkg/binaryinspector"
	"firmwareanalyzer/pkg/extractor"
)

// Format enumerates supported SBOM representations.
type Format string

const (
	// FormatSPDX emits a lightweight SPDX 2.3 JSON document.
	FormatSPDX Format = "spdx"
	// FormatCycloneDX emits a simplified CycloneDX 1.5 JSON document.
	FormatCycloneDX Format = "cyclonedx"
)

// Options control SBOM generation behaviour.
type Options struct {
	Format      Format
	ProductName string
}

// Package describes a software package present in the firmware image.
type Package struct {
	Name     string `json:"name"`
	Version  string `json:"version,omitempty"`
	Supplier string `json:"supplier,omitempty"`
	Path     string `json:"path,omitempty"`
}

// Document is the format-agnostic SBOM representation used internally.
type Document struct {
	Format     Format                `json:"format"`
	Created    time.Time             `json:"created"`
	Name       string                `json:"name"`
	Packages   []Package             `json:"packages"`
	Partitions []extractor.Partition `json:"partitions,omitempty"`
}

// Generator produces SBOM documents for extracted firmware trees.
type Generator struct {
	logger *log.Logger
	opts   Options
}

// NewGenerator constructs a Generator, discarding log output when logger is nil.
func NewGenerator(logger *log.Logger, opts Options) *Generator {
	if logger == nil {
		logger = log.New(io.Discard, "sbom", log.LstdFlags)
	}
	if opts.Format == "" {
		opts.Format = FormatSPDX
	}
	return &Generator{logger: logger, opts: opts}
}

// Generate inspects the extraction root and produces an SBOM document. Package
// information is sourced from package manager metadata when available and
// otherwise falls back to binaries discovered during inspection. Partition
// metadata is included to provide additional context for downstream tooling.
func (g *Generator) Generate(ctx context.Context, root string, binaries []binaryinspector.Result, partitions []extractor.Partition) (Document, error) {
	packages, err := g.detectPackages(ctx, root)
	if err != nil {
		return Document{}, err
	}
	if len(packages) == 0 {
		fallback := fallbackPackages(binaries)
		packages = append(packages, fallback...)
	}
	sort.Slice(packages, func(i, j int) bool {
		if packages[i].Name == packages[j].Name {
			return packages[i].Version < packages[j].Version
		}
		return packages[i].Name < packages[j].Name
	})
	name := g.opts.ProductName
	if name == "" {
		name = filepath.Base(root)
	}
	return Document{
		Format:     g.opts.Format,
		Created:    time.Now().UTC(),
		Name:       name,
		Packages:   packages,
		Partitions: partitions,
	}, nil
}

// WriteJSON serialises the SBOM document to the provided path.
func WriteJSON(doc Document, path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func (g *Generator) detectPackages(ctx context.Context, root string) ([]Package, error) {
	opkgDir := filepath.Join(root, "usr", "lib", "opkg", "info")
	entries, err := os.ReadDir(opkgDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read opkg info: %w", err)
	}
	var packages []Package
	for _, entry := range entries {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".control") {
			continue
		}
		controlPath := filepath.Join(opkgDir, entry.Name())
		pkg, err := parseControlFile(controlPath)
		if err != nil {
			g.logger.Printf("skip %s: %v", controlPath, err)
			continue
		}
		packages = append(packages, pkg)
	}
	return packages, nil
}

func parseControlFile(path string) (Package, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Package{}, err
	}
	lines := strings.Split(string(data), "\n")
	pkg := Package{Path: filepath.Dir(path)}
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(parts[0]))
		value := strings.TrimSpace(parts[1])
		switch key {
		case "package":
			pkg.Name = value
		case "version":
			pkg.Version = value
		case "maintainer":
			pkg.Supplier = value
		}
	}
	if pkg.Name == "" {
		return Package{}, fmt.Errorf("missing package name")
	}
	return pkg, nil
}

func fallbackPackages(binaries []binaryinspector.Result) []Package {
	seen := make(map[string]Package)
	for _, bin := range binaries {
		if bin.Path == "" || bin.Err != "" {
			continue
		}
		name := filepath.Base(bin.Path)
		if name == "" {
			continue
		}
		if _, exists := seen[name]; exists {
			continue
		}
		seen[name] = Package{Name: name, Path: bin.Path}
	}
	out := make([]Package, 0, len(seen))
	for _, pkg := range seen {
		out = append(out, pkg)
	}
	return out
}
