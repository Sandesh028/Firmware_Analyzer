package report

import (
	"fmt"
	"html/template"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"

	"firmwareanalyzer/pkg/binaryinspector"
	"firmwareanalyzer/pkg/configparser"
	"firmwareanalyzer/pkg/extractor"
	"firmwareanalyzer/pkg/filesystem"
	"firmwareanalyzer/pkg/secrets"
	"firmwareanalyzer/pkg/service"
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
			builder.WriteString("| Name | Type | Size (bytes) | Path |\n")
			builder.WriteString("| --- | --- | --- | --- |\n")
			for _, part := range summary.Extraction.Partitions {
				builder.WriteString(fmt.Sprintf("| %s | %s | %d | %s |\n", part.Name, part.Type, part.Size, part.Path))
			}
			builder.WriteString("\n")
		}
	}

	if len(summary.FileSystems) > 0 {
		builder.WriteString("## Filesystems\n")
		builder.WriteString("| Image | Type | Size (bytes) | Notes |\n")
		builder.WriteString("| --- | --- | --- | --- |\n")
		for _, fs := range summary.FileSystems {
			builder.WriteString(fmt.Sprintf("| %s | %s | %d | %s |\n", fs.ImagePath, fs.Type, fs.Size, fs.Notes))
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

	return builder.String()
}

// HTML renders a minimal HTML document embedding the Markdown content.
func (g *Generator) HTML(summary Summary) (string, error) {
	md := g.Markdown(summary)
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

// WriteFiles writes Markdown and HTML reports to the specified directory.
func (g *Generator) WriteFiles(summary Summary, outputDir string) (string, string, error) {
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return "", "", err
	}
	md := g.Markdown(summary)
	mdPath := filepath.Join(outputDir, "report.md")
	if err := os.WriteFile(mdPath, []byte(md), 0o644); err != nil {
		return "", "", err
	}
	html, err := g.HTML(summary)
	if err != nil {
		return "", "", err
	}
	htmlPath := filepath.Join(outputDir, "report.html")
	if err := os.WriteFile(htmlPath, []byte(html), 0o644); err != nil {
		return "", "", err
	}
	return mdPath, htmlPath, nil
}
