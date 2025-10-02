package report

import (
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"firmwareanalyzer/pkg/binaryinspector"
	"firmwareanalyzer/pkg/configparser"
	"firmwareanalyzer/pkg/extractor"
	"firmwareanalyzer/pkg/filesystem"
	"firmwareanalyzer/pkg/plugin"
	"firmwareanalyzer/pkg/sbom"
	"firmwareanalyzer/pkg/secrets"
	"firmwareanalyzer/pkg/service"
	"firmwareanalyzer/pkg/vuln"
)

// Summary aggregates analysis results for rendering.
type Summary struct {
	Firmware    string
	Extraction  *extractor.Result
	FileSystems []filesystem.Mount
	Configs     []configparser.Finding
	Services    []service.Service
	Secrets     []secrets.Finding
	Binaries    []binaryinspector.Result
	Vulnerable  []vuln.Finding
	SBOM        *sbom.Document
	SBOMPath    string
	Plugins     []plugin.Result
}

// Generator renders Markdown and HTML reports.
type Generator struct {
	logger *log.Logger
}

// NewGenerator returns a generator that discards log output when logger is nil.
func NewGenerator(logger *log.Logger) *Generator {
	if logger == nil {
		logger = log.New(io.Discard, "report", log.LstdFlags)
	}
	return &Generator{logger: logger}
}

// Markdown produces a Markdown report summarising the supplied analysis.
func (g *Generator) Markdown(summary Summary) string {
	var builder strings.Builder
	builder.WriteString("# Drone Firmware Analyzer Report\n\n")
	builder.WriteString(fmt.Sprintf("**Firmware:** %s\n\n", summary.Firmware))

	if summary.Extraction != nil {
		builder.WriteString("## Extraction\n")
		builder.WriteString(fmt.Sprintf("Output directory: `%s`\n\n", summary.Extraction.OutputDir))
		if len(summary.Extraction.Partitions) > 0 {
			builder.WriteString("| Name | Type | Size (bytes) | Offset | Notes | Path |\n")
			builder.WriteString("| --- | --- | --- | --- | --- | --- |\n")
			for _, part := range summary.Extraction.Partitions {
				offset := "-"
				if part.Offset > 0 {
					offset = fmt.Sprintf("%d", part.Offset)
				}
				notes := part.Notes
				if notes == "" {
					notes = "-"
				}
				builder.WriteString(fmt.Sprintf("| %s | %s | %d | %s | %s | %s |\n", part.Name, part.Type, part.Size, offset, notes, part.Path))
			}
			builder.WriteString("\n")
		}
	}

	if len(summary.FileSystems) > 0 {
		builder.WriteString("## Filesystems\n")
		builder.WriteString("| Image | Type | Size (bytes) | Offset | Notes |\n")
		builder.WriteString("| --- | --- | --- | --- | --- |\n")
		for _, fs := range summary.FileSystems {
			offset := "-"
			if fs.Offset > 0 {
				offset = fmt.Sprintf("%d", fs.Offset)
			}
			notes := fs.Notes
			if notes == "" {
				notes = "-"
			}
			builder.WriteString(fmt.Sprintf("| %s | %s | %d | %s | %s |\n", fs.ImagePath, fs.Type, fs.Size, offset, notes))
		}
		builder.WriteString("\n")
	}

	if len(summary.Configs) > 0 {
		builder.WriteString("## Configuration Findings\n")
		for _, cfg := range summary.Configs {
			builder.WriteString(fmt.Sprintf("### %s (%s)\n", cfg.File, strings.ToUpper(cfg.Format)))
			builder.WriteString("| Key | Value | Credential? |\n")
			builder.WriteString("| --- | --- | --- |\n")
			for _, param := range cfg.Params {
				cred := ""
				if param.Credential {
					cred = "⚠️"
				}
				builder.WriteString(fmt.Sprintf("| %s | %s | %s |\n", param.Key, param.Value, cred))
			}
			builder.WriteString("\n")
		}
	}

	if len(summary.Services) > 0 {
		builder.WriteString("## Services\n")
		builder.WriteString("| Name | Type | Path | Provides |\n")
		builder.WriteString("| --- | --- | --- | --- |\n")
		for _, svc := range summary.Services {
			builder.WriteString(fmt.Sprintf("| %s | %s | %s | %s |\n", svc.Name, svc.Type, svc.Path, strings.Join(svc.Provides, ", ")))
		}
		builder.WriteString("\n")
	}

	if len(summary.Secrets) > 0 {
		builder.WriteString("## Secrets\n")
		builder.WriteString("| File | Line | Rule | Match | Entropy |\n")
		builder.WriteString("| --- | --- | --- | --- | --- |\n")
		for _, sec := range summary.Secrets {
			builder.WriteString(fmt.Sprintf("| %s | %d | %s | `%s` | %.2f |\n", sec.File, sec.Line, sec.Rule, sec.Match, sec.Entropy))
		}
		builder.WriteString("\n")
	}

	if len(summary.Binaries) > 0 {
		builder.WriteString("## Binary Protections\n")
		builder.WriteString(binaryinspector.CollectMarkdownTable(summary.Binaries))
		builder.WriteString("\n")
	}

	if len(summary.Vulnerable) > 0 {
		builder.WriteString("## Vulnerabilities\n")
		builder.WriteString("| Path | Hash | CVEs | Error |\n")
		builder.WriteString("| --- | --- | --- | --- |\n")
		for _, vul := range summary.Vulnerable {
			ids := "-"
			if len(vul.CVEs) > 0 {
				var parts []string
				for _, c := range vul.CVEs {
					if c.ID != "" {
						parts = append(parts, c.ID)
					}
				}
				if len(parts) > 0 {
					ids = strings.Join(parts, ", ")
				}
			}
			hash := vul.Hash
			if hash == "" {
				hash = "-"
			}
			errMsg := "-"
			if vul.Error != "" {
				errMsg = vul.Error
			}
			builder.WriteString(fmt.Sprintf("| %s | %s | %s | %s |\n", vul.Path, hash, ids, errMsg))
		}
		builder.WriteString("\n")
	}

	if summary.SBOM != nil {
		builder.WriteString("## SBOM\n")
		format := strings.ToUpper(string(summary.SBOM.Format))
		builder.WriteString(fmt.Sprintf("Generated %s document with %d packages.\n\n", format, len(summary.SBOM.Packages)))
		if summary.SBOMPath != "" {
			builder.WriteString(fmt.Sprintf("File: `%s`\n\n", summary.SBOMPath))
		}
	}

	if len(summary.Plugins) > 0 {
		builder.WriteString("## Plugin Findings\n")
		for _, res := range summary.Plugins {
			builder.WriteString(fmt.Sprintf("### %s\n", res.Plugin))
			if res.Error != "" {
				builder.WriteString(fmt.Sprintf("Error: %s\n\n", res.Error))
				continue
			}
			if len(res.Findings) == 0 {
				builder.WriteString("No findings reported.\n\n")
				continue
			}
			builder.WriteString("| Summary | Severity | Details |\n")
			builder.WriteString("| --- | --- | --- |\n")
			for _, finding := range res.Findings {
				severity := finding.Severity
				if severity == "" {
					severity = "info"
				}
				details := "-"
				if len(finding.Details) > 0 {
					keys := make([]string, 0, len(finding.Details))
					for k := range finding.Details {
						keys = append(keys, k)
					}
					sort.Strings(keys)
					pairs := make([]string, 0, len(keys))
					for _, k := range keys {
						pairs = append(pairs, fmt.Sprintf("%s=%v", k, finding.Details[k]))
					}
					details = strings.Join(pairs, "; ")
				}
				builder.WriteString(fmt.Sprintf("| %s | %s | %s |\n", finding.Summary, severity, details))
			}
			builder.WriteString("\n")
		}
	}

	return builder.String()
}

// HTML renders a minimal HTML document embedding the Markdown content.
func (g *Generator) HTML(summary Summary) (string, error) {
	return g.htmlFromMarkdown(g.Markdown(summary))
}

// Formats declares which report artefacts should be written.
type Formats struct {
	Markdown bool
	HTML     bool
	JSON     bool
}

// DefaultFormats enables all report formats.
var DefaultFormats = Formats{Markdown: true, HTML: true, JSON: true}

// Paths describes the artefacts written to disk.
type Paths struct {
	Markdown string
	HTML     string
	JSON     string
}

// WriteFiles writes selected report formats to the specified directory.
func (g *Generator) WriteFiles(summary Summary, outputDir string, formats Formats) (Paths, error) {
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return Paths{}, err
	}
	if !formats.Markdown && !formats.HTML && !formats.JSON {
		formats = DefaultFormats
	}
	var paths Paths
	var md string
	if formats.Markdown || formats.HTML {
		md = g.Markdown(summary)
	}
	if formats.Markdown {
		mdPath := filepath.Join(outputDir, "report.md")
		if err := os.WriteFile(mdPath, []byte(md), 0o644); err != nil {
			return Paths{}, err
		}
		paths.Markdown = mdPath
	}
	if formats.HTML {
		html, err := g.htmlFromMarkdown(md)
		if err != nil {
			return Paths{}, err
		}
		htmlPath := filepath.Join(outputDir, "report.html")
		if err := os.WriteFile(htmlPath, []byte(html), 0o644); err != nil {
			return Paths{}, err
		}
		paths.HTML = htmlPath
	}
	if formats.JSON {
		data, err := json.MarshalIndent(summary, "", "  ")
		if err != nil {
			return Paths{}, err
		}
		jsonPath := filepath.Join(outputDir, "report.json")
		if err := os.WriteFile(jsonPath, data, 0o644); err != nil {
			return Paths{}, err
		}
		paths.JSON = jsonPath
	}
	return paths, nil
}

func (g *Generator) htmlFromMarkdown(md string) (string, error) {
	tmpl := `<html><head><meta charset="utf-8"><title>Drone Firmware Analyzer Report</title></head><body><pre>{{.}}</pre></body></html>`
	t, err := template.New("report").Parse(tmpl)
	if err != nil {
		return "", err
	}
	var builder strings.Builder
	if err := t.Execute(&builder, md); err != nil {
		return "", err
	}
	return builder.String(), nil
}
