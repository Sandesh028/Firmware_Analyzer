package report

import (
	"bytes"
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
	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/extension"
	html "github.com/yuin/goldmark/renderer/html"
)

// Summary aggregates analysis results for rendering.
type Summary struct {
	Firmware       string
	Extraction     *extractor.Result
	FileSystems    []filesystem.Mount
	Configs        []configparser.Finding
	Services       []service.Service
	Secrets        []secrets.Finding
	Binaries       []binaryinspector.Result
	Vulnerable     []vuln.Finding
	PackageVulns   []vuln.PackageFinding
	SBOM           *sbom.Document
	SBOMPath       string
	SBOMPaths      []string
	SBOMSignatures []string
	Plugins        []plugin.Result
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
	builder.WriteString(fmt.Sprintf("**Firmware:** `%s`\n\n", mdEscape(summary.Firmware)))

	writeSummaryOverview(&builder, summary)

	if summary.Extraction != nil {
		builder.WriteString("## Extraction\n")
		builder.WriteString(fmt.Sprintf("Workspace root: %s\n\n", mdCode(summary.Extraction.OutputDir)))
		if len(summary.Extraction.Partitions) > 0 {
			builder.WriteString("| Artifact | Type | Size (bytes) | Offset (bytes) | Entropy | Compression | Notes | Location |\n")
			builder.WriteString("| --- | --- | --- | --- | --- | --- | --- | --- |\n")
			for _, part := range summary.Extraction.Partitions {
				offset := "-"
				if part.Offset > 0 {
					offset = fmt.Sprintf("%d", part.Offset)
				}
				entropy := "-"
				if part.Entropy > 0 {
					entropy = fmt.Sprintf("%.2f", part.Entropy)
				}
				compression := part.Compression
				if compression == "" {
					compression = "-"
				}
				notes := part.Notes
				if notes == "" {
					notes = "-"
				}
				builder.WriteString(fmt.Sprintf("| %s | %s | %d | %s | %s | %s | %s | %s |\n",
					mdEscape(part.Name),
					mdEscape(part.Type),
					part.Size,
					offset,
					entropy,
					compression,
					mdEscape(notes),
					mdCode(part.Path),
				))
			}
			builder.WriteString("\n")
			builder.WriteString("> **Legend:** Artifact – discovered image or directory; Entropy – 0–8 Shannon estimate; Compression – heuristic classification; Notes – detection rationale; Location – normalized workspace path.\n\n")
		}
	}

	if len(summary.FileSystems) > 0 {
		builder.WriteString("## Filesystems\n")
		builder.WriteString("| Image | Type | Size (bytes) | Offset (bytes) | Notes |\n")
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
			builder.WriteString(fmt.Sprintf("| %s | %s | %d | %s | %s |\n",
				mdCode(fs.ImagePath),
				mdEscape(fs.Type),
				fs.Size,
				offset,
				mdEscape(notes),
			))
		}
		builder.WriteString("\n")
		builder.WriteString("> **Legend:** Image – on-disk artifact analysed; Type – inferred filesystem; Offset – bytes from firmware start (if available); Notes – detection hints.\n\n")
	}

	if len(summary.Configs) > 0 {
		builder.WriteString("## Configuration Findings\n")
		for _, cfg := range summary.Configs {
			builder.WriteString(fmt.Sprintf("### %s (%s)\n", mdCode(cfg.File), strings.ToUpper(mdEscape(string(cfg.Format)))))
			builder.WriteString("> Extracted key/value pairs from configuration data. Entries flagged with ⚠️ look like credentials.\n\n")
			builder.WriteString("| Key | Value | Credential? |\n")
			builder.WriteString("| --- | --- | --- |\n")
			for _, param := range cfg.Params {
				cred := ""
				if param.Credential {
					cred = "⚠️"
				}
				builder.WriteString(fmt.Sprintf("| %s | %s | %s |\n",
					mdEscape(param.Key),
					mdEscape(param.Value),
					cred,
				))
			}
			builder.WriteString("\n")
		}
	}

	if len(summary.Services) > 0 {
		builder.WriteString("## Services\n")
		builder.WriteString("> Detected init/system services that ship with the firmware.\n\n")
		builder.WriteString("| Name | Type | Path | Provides |\n")
		builder.WriteString("| --- | --- | --- | --- |\n")
		for _, svc := range summary.Services {
			builder.WriteString(fmt.Sprintf("| %s | %s | %s | %s |\n",
				mdEscape(svc.Name),
				mdEscape(svc.Type),
				mdCode(svc.Path),
				mdEscape(strings.Join(svc.Provides, ", ")),
			))
		}
		builder.WriteString("\n")
	}

	if len(summary.Secrets) > 0 {
		builder.WriteString("## Secrets\n")
		builder.WriteString("> Potential credentials, tokens, or keys located via pattern and entropy checks.\n\n")
		builder.WriteString("| File | Line | Rule | Match | Entropy |\n")
		builder.WriteString("| --- | --- | --- | --- | --- |\n")
		for _, sec := range summary.Secrets {
			builder.WriteString(fmt.Sprintf("| %s | %d | %s | %s | %.2f |\n",
				mdCode(sec.File),
				sec.Line,
				mdEscape(sec.Rule),
				mdCode(sec.Match),
				sec.Entropy,
			))
		}
		builder.WriteString("\n")
	}

	if len(summary.Binaries) > 0 {
		builder.WriteString("## Binary Protections\n")
		builder.WriteString("> RELRO/NX/PIE status for discovered ELF binaries. Use this to prioritise hardening gaps.\n\n")
		builder.WriteString(binaryinspector.CollectMarkdownTable(summary.Binaries))
		builder.WriteString("\n")
	}

	if len(summary.Vulnerable) > 0 {
		builder.WriteString("## Vulnerabilities\n")
		builder.WriteString("> Hash-based lookups from the bundled database and optional OSV/NVD queries.\n\n")
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
			builder.WriteString(fmt.Sprintf("| %s | %s | %s | %s |\n",
				mdCode(vul.Path),
				mdEscape(hash),
				mdEscape(ids),
				mdEscape(errMsg),
			))
		}
		builder.WriteString("\n")
	}

	if len(summary.PackageVulns) > 0 {
		builder.WriteString("## Package Vulnerabilities\n")
		builder.WriteString("> Package inventory lookups using SBOM metadata combined with OSV/NVD responses.\n\n")
		builder.WriteString("| Package | Version | Source | CVEs | Notes |\n")
		builder.WriteString("| --- | --- | --- | --- | --- |\n")
		for _, finding := range summary.PackageVulns {
			pkg := finding.Package
			notes := "-"
			if finding.Error != "" {
				notes = mdEscape(finding.Error)
			}
			builder.WriteString(fmt.Sprintf("| %s | %s | %s | %s | %s |\n",
				mdEscape(pkg.Name),
				mdEscape(valueOrDash(pkg.Version)),
				mdEscape(valueOrDash(pkg.Supplier)),
				formatCVEMarkdown(finding.CVEs),
				notes,
			))
		}
		builder.WriteString("\n")
	}

	if summary.SBOM != nil {
		builder.WriteString("## SBOM\n")
		format := strings.ToUpper(string(summary.SBOM.Format))
		builder.WriteString(fmt.Sprintf("Generated %s document with %d packages.\n\n", format, len(summary.SBOM.Packages)))
		switch {
		case len(summary.SBOMPaths) > 0:
			builder.WriteString("Files:\n")
			for _, p := range summary.SBOMPaths {
				builder.WriteString(fmt.Sprintf("- %s\n", mdCode(p)))
			}
			builder.WriteString("\n")
		case summary.SBOMPath != "":
			builder.WriteString(fmt.Sprintf("File: %s\n\n", mdCode(summary.SBOMPath)))
		}
		if len(summary.SBOMSignatures) > 0 {
			builder.WriteString("Signatures:\n")
			for _, sig := range summary.SBOMSignatures {
				builder.WriteString(fmt.Sprintf("- %s\n", mdCode(sig)))
			}
			builder.WriteString("\n")
		}
	}

	if len(summary.Plugins) > 0 {
		builder.WriteString("## Plugin Findings\n")
		builder.WriteString("> Results provided by external extensions. Errors are reported per plugin.\n\n")
		for _, res := range summary.Plugins {
			builder.WriteString(fmt.Sprintf("### %s\n", mdEscape(res.Plugin)))
			if res.Error != "" {
				builder.WriteString(fmt.Sprintf("Error: %s\n\n", mdEscape(res.Error)))
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
				builder.WriteString(fmt.Sprintf("| %s | %s | %s |\n",
					mdEscape(finding.Summary),
					mdEscape(severity),
					mdEscape(details),
				))
			}
			builder.WriteString("\n")
		}
	}

	return builder.String()
}

// HTML renders a minimal HTML document embedding the Markdown content.
func (g *Generator) HTML(summary Summary) (string, error) {
	md := g.Markdown(summary)
	return g.buildHTML(summary, md)
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
		html, err := g.buildHTML(summary, md)
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

// LoadJSON reads a JSON summary generated by WriteFiles.
func LoadJSON(path string) (Summary, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Summary{}, err
	}
	var summary Summary
	if err := json.Unmarshal(data, &summary); err != nil {
		return Summary{}, err
	}
	return summary, nil
}

func (g *Generator) buildHTML(summary Summary, md string) (string, error) {
	markdownHTML, err := g.renderMarkdown(md)
	if err != nil {
		return "", err
	}
	summaryData, err := json.Marshal(summary)
	if err != nil {
		return "", err
	}
	payload := struct {
		SummaryJSON  template.JS
		MarkdownHTML template.HTML
	}{
		SummaryJSON:  template.JS(string(summaryData)),
		MarkdownHTML: markdownHTML,
	}
	tmpl, err := template.New("interactive").Parse(interactiveHTMLTemplate)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, payload); err != nil {
		return "", err
	}
	return buf.String(), nil
}

func (g *Generator) renderMarkdown(md string) (template.HTML, error) {
	var buf bytes.Buffer
	renderer := goldmark.New(
		goldmark.WithExtensions(extension.GFM, extension.Table, extension.Strikethrough, extension.DefinitionList, extension.TaskList),
		goldmark.WithRendererOptions(html.WithHardWraps(), html.WithXHTML()),
	)
	if err := renderer.Convert([]byte(md), &buf); err != nil {
		return "", err
	}
	return template.HTML(buf.String()), nil
}

func writeSummaryOverview(builder *strings.Builder, summary Summary) {
	builder.WriteString("## Analysis Overview\n")
	builder.WriteString("| Module | Findings | Highlights |\n")
	builder.WriteString("| --- | --- | --- |\n")

	rows := []struct {
		module   string
		findings string
		note     string
	}{}

	if summary.Extraction != nil {
		count := len(summary.Extraction.Partitions)
		note := fmt.Sprintf("Workspace %s", mdCode(summary.Extraction.OutputDir))
		if count == 0 {
			note = "No partitions detected."
		}
		rows = append(rows, struct {
			module   string
			findings string
			note     string
		}{"Extraction", pluralise(count, "partition"), note})
	} else {
		rows = append(rows, struct {
			module   string
			findings string
			note     string
		}{"Extraction", "0 partitions", "Module did not run."})
	}

	fsCount := len(summary.FileSystems)
	fsTypes := uniqueTypes(summary.FileSystems)
	rows = append(rows, struct {
		module   string
		findings string
		note     string
	}{"Filesystem detection", pluralise(fsCount, "filesystem"), highlightOrDefault(fsTypes, "No filesystem artefacts flagged.")})

	cfgCount := len(summary.Configs)
	cfgFormats := uniqueConfigFormats(summary.Configs)
	cfgNote := highlightOrDefault(cfgFormats, "No configuration files parsed.")
	rows = append(rows, struct {
		module   string
		findings string
		note     string
	}{"Configuration analysis", pluralise(cfgCount, "file"), cfgNote})

	svcCount := len(summary.Services)
	svcNote := "No services discovered."
	if svcCount > 0 {
		svcNote = fmt.Sprintf("Examples include %s", mdEscape(summary.Services[0].Name))
	}
	rows = append(rows, struct {
		module   string
		findings string
		note     string
	}{"Service inventory", pluralise(svcCount, "service"), svcNote})

	secretCount := len(summary.Secrets)
	secretNote := "No patterns matched."
	if secretCount > 0 {
		secretNote = fmt.Sprintf("Highest entropy %.2f", maxEntropy(summary.Secrets))
	}
	rows = append(rows, struct {
		module   string
		findings string
		note     string
	}{"Secret scanning", pluralise(secretCount, "finding"), secretNote})

	binCount := len(summary.Binaries)
	binNote := "No ELF binaries inspected."
	if binCount > 0 {
		binNote = fmt.Sprintf("%d missing NX", countWithoutNX(summary.Binaries))
	}
	rows = append(rows, struct {
		module   string
		findings string
		note     string
	}{"Binary protections", pluralise(binCount, "binary"), binNote})

	vulnCount := len(summary.Vulnerable)
	vulnNote := "No hashes matched known CVEs."
	if vulnCount > 0 {
		vulnNote = fmt.Sprintf("%d entries with CVE IDs", countWithCVEs(summary.Vulnerable))
	}
	rows = append(rows, struct {
		module   string
		findings string
		note     string
	}{"Vulnerability lookup", pluralise(vulnCount, "artifact"), vulnNote})

	pkgVulnCount := len(summary.PackageVulns)
	pkgNote := "No package CVEs identified."
	if pkgVulnCount > 0 {
		pkgNote = fmt.Sprintf("%d packages with advisories", countPackageCVEs(summary.PackageVulns))
	}
	rows = append(rows, struct {
		module   string
		findings string
		note     string
	}{"Package advisories", pluralise(pkgVulnCount, "package"), pkgNote})

	sbomNote := "SBOM generation disabled."
	if summary.SBOM != nil {
		sbomNote = fmt.Sprintf("Format %s", strings.ToUpper(string(summary.SBOM.Format)))
	}
	rows = append(rows, struct {
		module   string
		findings string
		note     string
	}{"SBOM", sbomStatus(summary), sbomNote})

	pluginCount := len(summary.Plugins)
	pluginNote := "No plugins executed."
	if pluginCount > 0 {
		names := make([]string, 0, len(summary.Plugins))
		for _, p := range summary.Plugins {
			names = append(names, p.Plugin)
		}
		sort.Strings(names)
		pluginNote = fmt.Sprintf("Plugins: %s", mdEscape(strings.Join(names, ", ")))
	}
	rows = append(rows, struct {
		module   string
		findings string
		note     string
	}{"Plugins", pluralise(pluginCount, "result"), pluginNote})

	for _, row := range rows {
		builder.WriteString(fmt.Sprintf("| %s | %s | %s |\n",
			mdEscape(row.module),
			mdEscape(row.findings),
			mdEscape(row.note),
		))
	}
	builder.WriteString("\n")
}

func mdEscape(value string) string {
	value = strings.ReplaceAll(value, "|", "\\|")
	value = strings.ReplaceAll(value, "\n", "<br>")
	return value
}

func mdCode(value string) string {
	return fmt.Sprintf("`%s`", mdEscape(value))
}

func pluralise(count int, singular string) string {
	label := singular
	if count != 1 {
		label = singular + "s"
	}
	return fmt.Sprintf("%d %s", count, label)
}

func highlightOrDefault(values []string, fallback string) string {
	if len(values) == 0 {
		return fallback
	}
	sort.Strings(values)
	return strings.Join(values, ", ")
}

func uniqueTypes(mounts []filesystem.Mount) []string {
	seen := map[string]struct{}{}
	for _, m := range mounts {
		if m.Type == "" {
			continue
		}
		seen[m.Type] = struct{}{}
	}
	return mapKeys(seen)
}

func uniqueConfigFormats(cfgs []configparser.Finding) []string {
	seen := map[string]struct{}{}
	for _, cfg := range cfgs {
		if cfg.Format == "" {
			continue
		}
		seen[strings.ToUpper(string(cfg.Format))] = struct{}{}
	}
	return mapKeys(seen)
}

func mapKeys(m map[string]struct{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func maxEntropy(findings []secrets.Finding) float64 {
	max := 0.0
	for _, f := range findings {
		if f.Entropy > max {
			max = f.Entropy
		}
	}
	return max
}

func countWithoutNX(results []binaryinspector.Result) int {
	count := 0
	for _, res := range results {
		if !res.NXEnabled {
			count++
		}
	}
	return count
}

func countWithCVEs(findings []vuln.Finding) int {
	count := 0
	for _, f := range findings {
		if len(f.CVEs) > 0 {
			count++
		}
	}
	return count
}

func countPackageCVEs(findings []vuln.PackageFinding) int {
	count := 0
	for _, f := range findings {
		if len(f.CVEs) > 0 {
			count++
		}
	}
	return count
}

func sbomStatus(summary Summary) string {
	if summary.SBOM == nil {
		return "not generated"
	}
	if len(summary.SBOMPaths) > 0 {
		return fmt.Sprintf("%d artefacts", len(summary.SBOMPaths))
	}
	if summary.SBOMPath != "" {
		return "1 artefact"
	}
	return "generated"
}

func valueOrDash(value string) string {
	if strings.TrimSpace(value) == "" {
		return "-"
	}
	return value
}

func formatCVEMarkdown(cves []vuln.CVE) string {
	if len(cves) == 0 {
		return "-"
	}
	parts := make([]string, 0, len(cves))
	for _, c := range cves {
		label := mdEscape(c.ID)
		sev := strings.ToUpper(strings.TrimSpace(c.Severity))
		if sev != "" {
			label += fmt.Sprintf(" (%s)", mdEscape(sev))
		}
		parts = append(parts, label)
	}
	return strings.Join(parts, "<br/>")
}

const interactiveHTMLTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Drone Firmware Analyzer Report</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
:root { color-scheme: light; }
body { font-family: 'Inter', 'Segoe UI', sans-serif; margin: 0; background: #f4f6fb; color: #1f2933; }
a { color: #1d4ed8; text-decoration: none; }
a:hover { text-decoration: underline; }
header { background: linear-gradient(135deg, #4338ca, #6366f1); color: #fff; padding: 48px 32px 96px 32px; text-align: center; }
header h1 { margin: 0; font-size: 2.4rem; font-weight: 700; }
header p { margin-top: 10px; font-size: 1.05rem; opacity: 0.9; }
header p.meta { margin-top: 18px; font-size: 0.95rem; opacity: 0.85; }
header code { background: rgba(255,255,255,0.15); padding: 4px 8px; border-radius: 6px; color: #fff; }
main { max-width: 1200px; margin: -60px auto 48px; padding: 0 24px 80px; }
.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 16px; margin-bottom: 32px; }
.card { background: #fff; border-radius: 16px; padding: 18px 20px; box-shadow: 0 18px 40px rgba(15, 23, 42, 0.12); display: flex; flex-direction: column; gap: 6px; }
.card .value { font-size: 1.85rem; font-weight: 700; color: #111827; }
.card .label { font-size: 0.92rem; text-transform: uppercase; letter-spacing: 0.05em; color: #6b7280; }
.card .hint { font-size: 0.82rem; color: #475569; }
.panel { background: #fff; border-radius: 18px; padding: 24px 24px 30px; margin-bottom: 28px; box-shadow: 0 18px 36px rgba(15, 23, 42, 0.08); }
.panel h2 { margin-top: 0; font-size: 1.4rem; color: #1e1b4b; }
.panel p.description { margin-top: 4px; color: #475569; }
.table-container { margin-top: 14px; }
.search { width: 100%; padding: 10px 12px; border: 1px solid #d1d5db; border-radius: 10px; font-size: 0.95rem; margin-bottom: 12px; }
.data-table { width: 100%; border-collapse: collapse; font-size: 0.94rem; }
.data-table th { background: #eef2ff; color: #1e1b4b; text-align: left; padding: 0.65rem 0.75rem; border-bottom: 1px solid #d6dcf5; }
.data-table td { padding: 0.6rem 0.75rem; border-bottom: 1px solid #e2e8f0; vertical-align: top; color: #1f2933; }
.data-table tr:nth-child(even) td { background: #f8fafc; }
.badge { display: inline-flex; align-items: center; gap: 4px; border-radius: 999px; font-size: 0.78rem; padding: 2px 10px; font-weight: 600; }
.badge-ok { background: rgba(16, 185, 129, 0.15); color: #047857; }
.badge-warn { background: rgba(248, 113, 113, 0.18); color: #b91c1c; }
.badge-critical { background: rgba(248, 113, 113, 0.2); color: #991b1b; }
.badge-high { background: rgba(249, 115, 22, 0.2); color: #c2410c; }
.badge-medium { background: rgba(234, 179, 8, 0.22); color: #854d0e; }
.badge-low { background: rgba(16, 185, 129, 0.18); color: #166534; }
.badge-info { background: rgba(59, 130, 246, 0.18); color: #1d4ed8; }
.empty { color: #64748b; font-style: italic; margin: 12px 0; }
.muted { color: #94a3b8; }
.cve-list { margin: 0; padding-left: 1.1rem; }
.cve-list li { margin-bottom: 0.5rem; }
.cve-list .refs { display: block; font-size: 0.82rem; color: #2563eb; margin-top: 0.2rem; overflow-wrap: anywhere; }
.cve-list .desc { display: block; font-size: 0.82rem; color: #475569; margin-top: 0.25rem; }
.artefact-list { list-style: none; padding: 0; margin: 0; }
.artefact-list li { display: flex; justify-content: space-between; gap: 1rem; padding: 0.55rem 0; border-bottom: 1px solid #e2e8f0; }
.artefact-list span.label { font-weight: 600; color: #1e1b4b; }
.artefact-list code { background: #f1f5f9; padding: 0.25rem 0.45rem; border-radius: 6px; color: #334155; }
.markdown-body { background: #f8fafc; padding: 1.1rem; border-radius: 12px; border: 1px solid #e2e8f0; overflow-x: auto; }
#binary-chart { max-width: 100%; margin-top: 12px; }
#binary-chart-empty { margin-top: 8px; }
details summary { cursor: pointer; font-weight: 600; }
.hidden { display: none; }
@media (max-width: 720px) {
  header { padding: 36px 20px 80px; }
  header h1 { font-size: 2rem; }
  main { margin: -72px auto 32px; padding: 0 16px 60px; }
  .panel { padding: 20px; }
}
</style>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.4/dist/chart.umd.min.js"></script>
</head>
<body>
<header>
  <h1>Drone Firmware Analyzer</h1>
  <p>Interactive overview of the firmware inspection results.</p>
  <p class="meta" id="firmware-path"></p>
</header>
<main>
  <section class="cards" id="overview-cards"></section>
  <section class="panel" id="binary-panel">
    <h2>Binary Protections Overview</h2>
    <canvas id="binary-chart" height="120"></canvas>
    <p class="empty hidden" id="binary-chart-empty">No ELF binaries analysed.</p>
  </section>
  <section class="panel">
    <h2>Extraction</h2>
    <div class="table-container" id="extraction-table"></div>
  </section>
  <section class="panel">
    <h2>Filesystem Artefacts</h2>
    <div class="table-container" id="filesystem-table"></div>
  </section>
  <section class="panel">
    <h2>Configuration Files</h2>
    <div class="table-container" id="config-table"></div>
  </section>
  <section class="panel">
    <h2>Services</h2>
    <div class="table-container" id="service-table"></div>
  </section>
  <section class="panel">
    <h2>Secrets</h2>
    <div class="table-container" id="secret-table"></div>
  </section>
  <section class="panel">
    <h2>Binary Inventory</h2>
    <div class="table-container" id="binary-table"></div>
  </section>
  <section class="panel">
    <h2>Binary Vulnerabilities</h2>
    <div class="table-container" id="vulnerability-table"></div>
  </section>
  <section class="panel">
    <h2>Package Vulnerabilities</h2>
    <div class="table-container" id="package-table"></div>
  </section>
  <section class="panel">
    <h2>Plugin Findings</h2>
    <div class="table-container" id="plugin-table"></div>
  </section>
  <section class="panel">
    <h2>SBOM &amp; Artefacts</h2>
    <p class="description" id="sbom-meta"></p>
    <div id="artefact-list"></div>
    <p class="description" style="margin-top:14px; font-size:0.85rem;">Markdown and JSON reports are stored alongside this HTML file.</p>
  </section>
  <section class="panel">
    <h2>Raw Markdown Report</h2>
    <details>
      <summary>Toggle raw report</summary>
      <div class="markdown-body">{{.MarkdownHTML}}</div>
    </details>
  </section>
</main>
<script id="summary-data" type="application/json">{{.SummaryJSON}}</script>
<script>
(function() {
  const summaryElement = document.getElementById('summary-data');
  let summary = {};
  try {
    summary = JSON.parse(summaryElement.textContent || '{}');
  } catch (err) {
    console.error('Failed to parse summary JSON', err);
  }
  const ensureArray = (value) => Array.isArray(value) ? value : [];
  const escapeHTML = (value) => String(value ?? '').replace(/[&<>"']/g, (ch) => ({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"}[ch] || ch));
  const text = (value) => {
    const str = String(value ?? '').trim();
    return str === '' ? '-' : str;
  };
  const formatCount = (value) => (typeof value === 'number' && !Number.isNaN(value) ? value.toLocaleString() : '0');
  const formatBytes = (value) => (typeof value === 'number' && !Number.isNaN(value) ? value.toLocaleString() + ' bytes' : '-');
  const boolBadge = (flag) => flag ? '<span class="badge badge-ok">Yes</span>' : '<span class="badge badge-warn">No</span>';
  const severityBadge = (value) => {
    const sev = String(value || '').toLowerCase();
    if (!sev) return '';
    const map = { critical: 'badge-critical', high: 'badge-high', medium: 'badge-medium', moderate: 'badge-medium', low: 'badge-low', info: 'badge-info', informational: 'badge-info' };
    const cls = map[sev] || 'badge-info';
    return '<span class="badge ' + cls + '">' + escapeHTML(sev.toUpperCase()) + '</span>';
  };
  const stripHTML = (value) => String(value || '').replace(/<[^>]*>/g, ' ');
  const firmwareMeta = document.getElementById('firmware-path');
  if (firmwareMeta) {
    firmwareMeta.innerHTML = summary.Firmware ? 'Firmware image: <code>' + escapeHTML(summary.Firmware) + '</code>' : 'Firmware path not recorded.';
  }
  const computeBinaryStats = (binaries) => {
    let nxEnabled = 0, nxDisabled = 0, pieEnabled = 0, pieDisabled = 0;
    binaries.forEach((bin) => {
      if (bin && bin.NXEnabled) { nxEnabled++; } else { nxDisabled++; }
      if (bin && bin.PIEEnabled) { pieEnabled++; } else { pieDisabled++; }
    });
    return { nxEnabled, nxDisabled, pieEnabled, pieDisabled, total: binaries.length };
  };
  const renderCards = (summary) => {
    const container = document.getElementById('overview-cards');
    if (!container) { return; }
    container.innerHTML = '';
    const partitions = ensureArray(summary.Extraction && summary.Extraction.Partitions);
    const binaries = ensureArray(summary.Binaries);
    const secrets = ensureArray(summary.Secrets);
    const secretEntropy = secrets.reduce((max, entry) => Math.max(max, typeof entry.Entropy === 'number' ? entry.Entropy : 0), 0);
    const binaryStats = computeBinaryStats(binaries);
    const metrics = [
      { label: 'Partitions', value: partitions.length, hint: summary.Extraction && summary.Extraction.OutputDir ? 'Workspace ' + summary.Extraction.OutputDir : 'Extraction completed' },
      { label: 'Filesystems', value: ensureArray(summary.FileSystems).length },
      { label: 'Config files', value: ensureArray(summary.Configs).length },
      { label: 'Services', value: ensureArray(summary.Services).length },
      { label: 'Secrets', value: secrets.length, hint: secretEntropy > 0 ? 'Max entropy ' + secretEntropy.toFixed(2) : undefined },
      { label: 'Binaries', value: binaries.length, hint: binaryStats.nxDisabled > 0 ? binaryStats.nxDisabled + ' without NX' : undefined },
      { label: 'Binary CVEs', value: ensureArray(summary.Vulnerable).filter((item) => ensureArray(item.CVEs).length > 0).length },
      { label: 'Package CVEs', value: ensureArray(summary.PackageVulns).filter((item) => ensureArray(item.CVEs).length > 0).length },
      { label: 'Plugins', value: ensureArray(summary.Plugins).length },
      { label: 'SBOM artefacts', value: (ensureArray(summary.SBOMPaths).length || (summary.SBOM ? 1 : 0)) }
    ];
    metrics.forEach((metric) => {
      const card = document.createElement('div');
      card.className = 'card';
      const value = document.createElement('div');
      value.className = 'value';
      value.textContent = formatCount(metric.value);
      const label = document.createElement('div');
      label.className = 'label';
      label.textContent = metric.label;
      card.appendChild(value);
      card.appendChild(label);
      if (metric.hint) {
        const hint = document.createElement('div');
        hint.className = 'hint';
        hint.textContent = metric.hint;
        card.appendChild(hint);
      }
      container.appendChild(card);
    });
  };
  const renderBinaryChart = (binaries) => {
    const chartEl = document.getElementById('binary-chart');
    const emptyEl = document.getElementById('binary-chart-empty');
    if (!chartEl || !emptyEl) { return; }
    if (!binaries.length || typeof window.Chart === 'undefined') {
      chartEl.classList.add('hidden');
      emptyEl.classList.remove('hidden');
      return;
    }
    const stats = computeBinaryStats(binaries);
    if (!stats.total) {
      chartEl.classList.add('hidden');
      emptyEl.classList.remove('hidden');
      return;
    }
    emptyEl.classList.add('hidden');
    new window.Chart(chartEl.getContext('2d'), {
      type: 'bar',
      data: {
        labels: ['NX', 'PIE'],
        datasets: [
          { label: 'Enabled', data: [stats.nxEnabled, stats.pieEnabled], backgroundColor: '#10b981' },
          { label: 'Disabled', data: [stats.nxDisabled, stats.pieDisabled], backgroundColor: '#ef4444' }
        ]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { position: 'bottom' } },
        scales: { y: { beginAtZero: true, ticks: { precision: 0 } } }
      }
    });
  };
  const renderTable = (containerId, columns, rows) => {
    const container = document.getElementById(containerId);
    if (!container) { return; }
    container.innerHTML = '';
    if (!rows || !rows.length) {
      container.innerHTML = '<p class="empty">No data available.</p>';
      return;
    }
    const search = document.createElement('input');
    search.type = 'search';
    search.placeholder = 'Filter results...';
    search.className = 'search';
    container.appendChild(search);
    const table = document.createElement('table');
    table.className = 'data-table';
    const thead = document.createElement('thead');
    const headRow = document.createElement('tr');
    columns.forEach((col) => {
      const th = document.createElement('th');
      th.textContent = col.label;
      headRow.appendChild(th);
    });
    thead.appendChild(headRow);
    table.appendChild(thead);
    const tbody = document.createElement('tbody');
    rows.forEach((row) => {
      const tr = document.createElement('tr');
      let searchText = '';
      columns.forEach((col) => {
        const td = document.createElement('td');
        const value = row[col.field];
        if (col.isHTML) {
          td.innerHTML = value || '<span class="muted">-</span>';
        } else {
          td.textContent = text(value);
        }
        const searchValue = col.searchField ? row[col.searchField] : (col.isHTML ? stripHTML(value) : value);
        searchText += ' ' + (searchValue || '');
        tr.appendChild(td);
      });
      tr.dataset.search = searchText.toLowerCase();
      tbody.appendChild(tr);
    });
    table.appendChild(tbody);
    container.appendChild(table);
    search.addEventListener('input', () => {
      const term = search.value.toLowerCase();
      tbody.querySelectorAll('tr').forEach((row) => {
        row.style.display = term === '' || row.dataset.search.includes(term) ? '' : 'none';
      });
    });
  };
  const formatCVEList = (cves) => {
    const list = ensureArray(cves);
    if (!list.length) {
      return '<span class="muted">None</span>';
    }
    const items = list.map((cve) => {
      const id = escapeHTML(cve && cve.ID ? cve.ID : 'Unassigned');
      const badge = severityBadge(cve && cve.Severity);
      const description = cve && cve.Description ? '<span class="desc">' + escapeHTML(cve.Description) + '</span>' : '';
      const refs = ensureArray(cve && cve.References);
      let refHtml = '';
      if (refs.length) {
        const display = refs.slice(0, 3).map((url) => '<a href="' + escapeHTML(url) + '" target="_blank" rel="noopener">' + escapeHTML(url) + '</a>').join(', ');
        const extra = refs.length > 3 ? ' +' + (refs.length - 3) + ' more' : '';
        refHtml = '<span class="refs">' + display + extra + '</span>';
      }
      return '<li><strong>' + id + '</strong> ' + badge + description + refHtml + '</li>';
    });
    return '<ul class="cve-list">' + items.join('') + '</ul>';
  };
  const renderArtefacts = (containerId, summary) => {
    const container = document.getElementById(containerId);
    if (!container) { return; }
    container.innerHTML = '';
    const items = [];
    ensureArray(summary.SBOMPaths).forEach((path) => items.push({ label: 'SBOM', value: path }));
    ensureArray(summary.SBOMSignatures).forEach((path) => items.push({ label: 'Signature', value: path }));
    if (!items.length) {
      container.innerHTML = '<p class="empty">No SBOM artefacts generated. Enable --sbom-format to export SPDX or CycloneDX documents.</p>';
      return;
    }
    const list = document.createElement('ul');
    list.className = 'artefact-list';
    items.forEach((item) => {
      const li = document.createElement('li');
      const label = document.createElement('span');
      label.className = 'label';
      label.textContent = item.label;
      const value = document.createElement('code');
      value.textContent = item.value;
      li.appendChild(label);
      li.appendChild(value);
      list.appendChild(li);
    });
    container.appendChild(list);
  };
  const renderSBOMMeta = (summary) => {
    const meta = document.getElementById('sbom-meta');
    if (!meta) { return; }
    if (summary.SBOM && Array.isArray(summary.SBOM.Packages)) {
      meta.textContent = 'Generated ' + text(summary.SBOM.Format).toUpperCase() + ' document with ' + formatCount(summary.SBOM.Packages.length) + ' packages.';
    } else {
      meta.textContent = 'SBOM generation was not enabled for this run.';
    }
  };
  const extractionRows = ensureArray(summary.Extraction && summary.Extraction.Partitions).map((part) => ({
    artifact: '<code>' + escapeHTML(part.Name || '-') + '</code>',
    type: text(part.Type),
    size: part.Size ? formatBytes(part.Size) : '-',
    offset: part.Offset && part.Offset > 0 ? formatCount(part.Offset) : '-',
    entropy: typeof part.Entropy === 'number' && part.Entropy > 0 ? part.Entropy.toFixed(2) : '-',
    notes: escapeHTML(part.Notes || '-'),
    search: [part.Name, part.Type, part.Notes].join(' ')
  }));
  renderTable('extraction-table', [
    { label: 'Artifact', field: 'artifact', isHTML: true, searchField: 'search' },
    { label: 'Type', field: 'type' },
    { label: 'Size', field: 'size' },
    { label: 'Offset', field: 'offset' },
    { label: 'Entropy', field: 'entropy' },
    { label: 'Notes', field: 'notes', isHTML: true }
  ], extractionRows);
  const filesystemRows = ensureArray(summary.FileSystems).map((fs) => ({
    image: '<code>' + escapeHTML(fs.ImagePath || '-') + '</code>',
    type: text(fs.Type),
    size: fs.Size ? formatBytes(fs.Size) : '-',
    offset: fs.Offset && fs.Offset > 0 ? formatCount(fs.Offset) : '-',
    notes: escapeHTML(fs.Notes || '-'),
    search: [fs.ImagePath, fs.Type, fs.Notes].join(' ')
  }));
  renderTable('filesystem-table', [
    { label: 'Image', field: 'image', isHTML: true, searchField: 'search' },
    { label: 'Type', field: 'type' },
    { label: 'Size', field: 'size' },
    { label: 'Offset', field: 'offset' },
    { label: 'Notes', field: 'notes', isHTML: true }
  ], filesystemRows);
  const configRows = ensureArray(summary.Configs).map((cfg) => {
    const params = ensureArray(cfg.Params);
    const credentials = params.filter((p) => p && p.Credential).length;
    const example = params.length ? '<code>' + escapeHTML(params[0].Key || '') + '=' + escapeHTML(params[0].Value || '') + '</code>' : '<span class="muted">-</span>';
    return {
      file: '<code>' + escapeHTML(cfg.File || '-') + '</code>',
      format: text((cfg.Format || '').toUpperCase()),
      entries: formatCount(params.length),
      credentials: formatCount(credentials),
      example,
      search: [cfg.File, cfg.Format].join(' ')
    };
  });
  renderTable('config-table', [
    { label: 'File', field: 'file', isHTML: true, searchField: 'search' },
    { label: 'Format', field: 'format' },
    { label: 'Entries', field: 'entries' },
    { label: 'Credentials', field: 'credentials' },
    { label: 'Example', field: 'example', isHTML: true }
  ], configRows);
  const serviceRows = ensureArray(summary.Services).map((svc) => ({
    name: '<code>' + escapeHTML(svc.Name || '-') + '</code>',
    type: text(svc.Type),
    path: '<code>' + escapeHTML(svc.Path || '-') + '</code>',
    provides: ensureArray(svc.Provides).length ? escapeHTML(ensureArray(svc.Provides).join(', ')) : '<span class="muted">-</span>',
    search: [svc.Name, svc.Type, svc.Path, ensureArray(svc.Provides).join(' ')].join(' ')
  }));
  renderTable('service-table', [
    { label: 'Name', field: 'name', isHTML: true, searchField: 'search' },
    { label: 'Type', field: 'type' },
    { label: 'Path', field: 'path', isHTML: true },
    { label: 'Provides', field: 'provides', isHTML: true }
  ], serviceRows);
  const secretRows = ensureArray(summary.Secrets).map((sec) => ({
    file: '<code>' + escapeHTML(sec.File || '-') + '</code>',
    line: formatCount(typeof sec.Line === 'number' ? sec.Line : 0),
    rule: text(sec.Rule),
    match: '<code>' + escapeHTML(sec.Match || '-') + '</code>',
    entropy: typeof sec.Entropy === 'number' ? sec.Entropy.toFixed(2) : '-',
    search: [sec.File, sec.Rule, sec.Match].join(' ')
  }));
  renderTable('secret-table', [
    { label: 'File', field: 'file', isHTML: true, searchField: 'search' },
    { label: 'Line', field: 'line' },
    { label: 'Rule', field: 'rule' },
    { label: 'Match', field: 'match', isHTML: true },
    { label: 'Entropy', field: 'entropy' }
  ], secretRows);
  const binaryRows = ensureArray(summary.Binaries).map((bin) => ({
    path: '<code>' + escapeHTML(bin.Path || '-') + '</code>',
    type: text(bin.Type),
    arch: text(bin.Architecture),
    relro: text((bin.RELRO || '').toUpperCase()),
    nx: boolBadge(!!(bin && bin.NXEnabled)),
    pie: boolBadge(!!(bin && bin.PIEEnabled)),
    stripped: boolBadge(!!(bin && bin.Stripped)),
    interp: bin && bin.Interpreter ? '<code>' + escapeHTML(bin.Interpreter) + '</code>' : '<span class="muted">-</span>',
    search: [bin.Path, bin.Type, bin.Architecture, bin.Interpreter].join(' ')
  }));
  renderTable('binary-table', [
    { label: 'Path', field: 'path', isHTML: true, searchField: 'search' },
    { label: 'Type', field: 'type' },
    { label: 'Arch', field: 'arch' },
    { label: 'RELRO', field: 'relro' },
    { label: 'NX', field: 'nx', isHTML: true },
    { label: 'PIE', field: 'pie', isHTML: true },
    { label: 'Stripped', field: 'stripped', isHTML: true },
    { label: 'Interpreter', field: 'interp', isHTML: true }
  ], binaryRows);
  const vulnRows = ensureArray(summary.Vulnerable).map((vul) => ({
    path: '<code>' + escapeHTML(vul.Path || '-') + '</code>',
    hash: vul && vul.Hash ? '<code>' + escapeHTML(vul.Hash) + '</code>' : '<span class="muted">-</span>',
    cves: formatCVEList(vul && vul.CVEs),
    cveText: ensureArray(vul && vul.CVEs).map((cve) => [cve.ID, cve.Severity, ensureArray(cve.References).join(' ')].join(' ')).join(' '),
    error: vul && vul.Error ? escapeHTML(vul.Error) : '<span class="muted">-</span>',
    search: [vul.Path, vul.Hash, vul.Error].join(' ')
  }));
  renderTable('vulnerability-table', [
    { label: 'Path', field: 'path', isHTML: true, searchField: 'search' },
    { label: 'Hash', field: 'hash', isHTML: true },
    { label: 'CVEs', field: 'cves', isHTML: true, searchField: 'cveText' },
    { label: 'Error', field: 'error', isHTML: true }
  ], vulnRows);
  const packageRows = ensureArray(summary.PackageVulns).map((finding) => {
    const pkg = finding && finding.Package ? finding.Package : {};
    return {
      pkg: '<code>' + escapeHTML(pkg.Name || '-') + '</code>',
      version: text(pkg.Version),
      source: text(pkg.Supplier),
      cves: formatCVEList(finding && finding.CVEs),
      cveText: ensureArray(finding && finding.CVEs).map((cve) => [cve.ID, cve.Severity, ensureArray(cve.References).join(' ')].join(' ')).join(' '),
      notes: finding && finding.Error ? escapeHTML(finding.Error) : '<span class="muted">-</span>',
      search: [pkg.Name, pkg.Version, pkg.Supplier, finding && finding.Error].join(' ')
    };
  });
  renderTable('package-table', [
    { label: 'Package', field: 'pkg', isHTML: true, searchField: 'search' },
    { label: 'Version', field: 'version' },
    { label: 'Source', field: 'source' },
    { label: 'CVEs', field: 'cves', isHTML: true, searchField: 'cveText' },
    { label: 'Notes', field: 'notes', isHTML: true }
  ], packageRows);
  const pluginRows = ensureArray(summary.Plugins).map((plugin) => {
    const findings = ensureArray(plugin.Findings);
    const example = findings.length ? escapeHTML((findings[0].Severity ? findings[0].Severity.toUpperCase() + ': ' : '') + (findings[0].Summary || '')) : '-';
    return {
      plugin: text(plugin.Plugin),
      findings: formatCount(findings.length),
      example: example,
      error: plugin && plugin.Error ? '<span class="badge badge-warn">' + escapeHTML(plugin.Error) + '</span>' : '<span class="muted">-</span>',
      search: [plugin.Plugin, plugin.Error, example].join(' ')
    };
  });
  renderTable('plugin-table', [
    { label: 'Plugin', field: 'plugin', searchField: 'search' },
    { label: 'Findings', field: 'findings' },
    { label: 'Example', field: 'example', isHTML: true },
    { label: 'Error', field: 'error', isHTML: true }
  ], pluginRows);
  renderCards(summary);
  renderBinaryChart(ensureArray(summary.Binaries));
  renderArtefacts('artefact-list', summary);
  renderSBOMMeta(summary);
})();
</script>
</body>
</html>`
