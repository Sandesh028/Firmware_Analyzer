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
	// Prevent </script> from prematurely terminating the inline JSON payload.
	summaryData = bytes.ReplaceAll(summaryData, []byte("</"), []byte("<\\/"))
	payload := struct {
		SummaryJSON  template.JS
		MarkdownHTML template.HTML
		ChartJS      template.JS
		D3JS         template.JS
		VennJS       template.JS
		HTML2PDFJS   template.JS
	}{
		SummaryJSON:  template.JS(string(summaryData)),
		MarkdownHTML: markdownHTML,
		ChartJS:      template.JS(chartJS()),
		D3JS:         template.JS(d3JS()),
		VennJS:       template.JS(vennJS()),
		HTML2PDFJS:   template.JS(html2pdfJS()),
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
<style>
:root { color-scheme: light; }
body { font-family: 'Inter', 'Segoe UI', sans-serif; margin: 0; background: #f4f6fb; color: #1f2933; }
a { color: #1d4ed8; text-decoration: none; }
a:hover { text-decoration: underline; }
header { background: linear-gradient(135deg, #4338ca, #6366f1); color: #fff; padding: 48px 32px 96px 32px; }
.header-content { max-width: 1200px; margin: 0 auto; display: flex; flex-wrap: wrap; align-items: flex-end; justify-content: space-between; gap: 24px; }
header h1 { margin: 0; font-size: 2.6rem; font-weight: 700; }
header p { margin-top: 10px; font-size: 1.05rem; opacity: 0.92; }
header p.meta { margin-top: 18px; font-size: 0.95rem; opacity: 0.85; }
header code { background: rgba(255,255,255,0.18); padding: 4px 8px; border-radius: 6px; color: #fff; }
.header-actions { display: flex; gap: 12px; align-items: center; }
.action-button { border: none; background: #fbbf24; color: #1f2933; padding: 10px 18px; border-radius: 999px; font-weight: 600; cursor: pointer; box-shadow: 0 10px 24px rgba(15, 23, 42, 0.25); transition: transform 0.15s ease, box-shadow 0.15s ease; }
.action-button:hover { transform: translateY(-1px); box-shadow: 0 16px 32px rgba(15, 23, 42, 0.25); }
.action-button:disabled { cursor: wait; opacity: 0.7; box-shadow: none; }
.action-link { border: 1px solid rgba(255,255,255,0.6); padding: 10px 18px; border-radius: 999px; font-weight: 600; color: #fff; background: rgba(255,255,255,0.08); }
.action-link:hover { background: rgba(255,255,255,0.16); }
main { max-width: 1200px; margin: -70px auto 48px; padding: 0 24px 96px; }
.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 16px; margin-bottom: 32px; }
.card { background: #fff; border-radius: 16px; padding: 18px 20px; box-shadow: 0 18px 40px rgba(15, 23, 42, 0.12); display: flex; flex-direction: column; gap: 6px; }
.card .value { font-size: 1.9rem; font-weight: 700; color: #111827; }
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
#binary-chart { max-width: 100%; margin-top: 12px; min-height: 200px; }
#binary-chart-empty { margin-top: 8px; }
.insight-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 24px; margin-top: 18px; }
.insight { background: linear-gradient(180deg, rgba(79, 70, 229, 0.08), rgba(129, 140, 248, 0.12)); border-radius: 16px; padding: 16px; box-shadow: inset 0 1px 0 rgba(255,255,255,0.5); display: flex; flex-direction: column; }
.insight h3 { margin: 0 0 10px 0; font-size: 1.05rem; color: #312e81; }
.insight canvas { background: #fff; border-radius: 12px; padding: 10px; box-shadow: 0 12px 24px rgba(99, 102, 241, 0.12); }
#venn-chart { width: 100%; min-height: 320px; margin-top: 16px; }
.venn-area path { fill-opacity: 0.4; stroke-opacity: 0.7; stroke-width: 2px; }
.venn-area text { fill: #1e1b4b; font-size: 0.85rem; }
.legend { display: flex; flex-wrap: wrap; gap: 10px; margin-top: 12px; font-size: 0.85rem; color: #475569; }
.legend span { display: inline-flex; align-items: center; gap: 6px; }
.legend span::before { content: ''; display: inline-block; width: 12px; height: 12px; border-radius: 999px; background: currentColor; }
.controls { display: flex; flex-wrap: wrap; gap: 12px; margin-top: 12px; }
details summary { cursor: pointer; font-weight: 600; }
.hidden { display: none; }
@media (max-width: 720px) {
  header { padding: 36px 20px 86px; }
  header h1 { font-size: 2rem; }
  main { margin: -82px auto 32px; padding: 0 16px 72px; }
  .panel { padding: 20px; }
  .header-actions { width: 100%; justify-content: flex-start; }
}
</style>
<script>{{.ChartJS}}</script>
<script>{{.D3JS}}</script>
<script>{{.VennJS}}</script>
<script>{{.HTML2PDFJS}}</script>
</head>
<body>
<header>
  <div class="header-content">
    <div>
      <h1>Drone Firmware Analyzer</h1>
      <p>Interactive overview of the firmware inspection results with drill-down tables and visual analytics.</p>
      <p class="meta" id="firmware-path"></p>
    </div>
    <div class="header-actions">
      <button id="pdf-button" class="action-button" type="button">Download PDF</button>
      <a class="action-link" id="markdown-download" href="report.md" download>Markdown</a>
      <a class="action-link" id="json-download" href="report.json" download>JSON</a>
    </div>
  </div>
</header>
<main>
  <section class="cards" id="overview-cards"></section>
  <section class="panel insights">
    <h2>Insights &amp; Statistics</h2>
    <p class="description">Visualise how protections, secrets, and vulnerabilities intersect so you can focus on the riskiest artefacts first.</p>
    <div class="insight-grid">
      <div class="insight">
        <h3>Partition Composition</h3>
        <canvas id="partition-chart" height="200"></canvas>
        <p class="empty hidden" id="partition-chart-empty">No partitions discovered.</p>
      </div>
      <div class="insight">
        <h3>Secret Rule Distribution</h3>
        <canvas id="secret-chart" height="200"></canvas>
        <p class="empty hidden" id="secret-chart-empty">No secrets detected.</p>
      </div>
      <div class="insight">
        <h3>Vulnerability Severity</h3>
        <canvas id="severity-chart" height="200"></canvas>
        <p class="empty hidden" id="severity-chart-empty">No CVEs recorded.</p>
      </div>
    </div>
  </section>
  <section class="panel" id="binary-panel">
    <h2>Binary Protections Overview</h2>
    <p class="description">Compare exploit mitigations across analysed ELF binaries.</p>
    <canvas id="binary-chart" height="160"></canvas>
    <p class="empty hidden" id="binary-chart-empty">No ELF binaries analysed.</p>
  </section>
  <section class="panel" id="relationship-panel">
    <h2>Configuration &amp; Service Relationship Map</h2>
    <p class="description">Shows directories that simultaneously host configuration files, secrets, or service definitions.</p>
    <div id="venn-chart"></div>
    <p class="empty hidden" id="venn-empty">Not enough overlapping artefacts to render a Venn diagram.</p>
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
    <p class="description" style="margin-top:14px; font-size:0.85rem;">All report formats are stored next to this HTML file for offline archiving.</p>
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
  const getDir = (path) => {
    if (!path) return '';
    const normalised = String(path).replace(/\\+/g, '/');
    if (!normalised.includes('/')) return normalised;
    return normalised.split('/').slice(0, -1).join('/') || normalised;
  };
  const firmwareMeta = document.getElementById('firmware-path');
  if (firmwareMeta) {
    firmwareMeta.innerHTML = summary.Firmware ? 'Firmware image: <code>' + escapeHTML(summary.Firmware) + '</code>' : 'Firmware path not recorded.';
  }
  const computeBinaryStats = (binaries) => {
    let nxEnabled = 0, nxDisabled = 0, pieEnabled = 0, pieDisabled = 0, relroFull = 0, relroPartial = 0, relroNone = 0;
    binaries.forEach((bin) => {
      if (bin && bin.NXEnabled) { nxEnabled++; } else { nxDisabled++; }
      if (bin && bin.PIEEnabled) { pieEnabled++; } else { pieDisabled++; }
      const relro = String(bin && bin.RELRO || '').toLowerCase();
      if (relro === 'full') relroFull++;
      else if (relro === 'partial') relroPartial++;
      else relroNone++;
    });
    return { nxEnabled, nxDisabled, pieEnabled, pieDisabled, relroFull, relroPartial, relroNone, total: binaries.length };
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
    const vulnTotal = ensureArray(summary.Vulnerable).reduce((count, item) => count + ensureArray(item.CVEs).length, 0);
    const pkgVulnTotal = ensureArray(summary.PackageVulns).reduce((count, item) => count + ensureArray(item.CVEs).length, 0);
    const metrics = [
      { label: 'Partitions', value: partitions.length, hint: summary.Extraction && summary.Extraction.OutputDir ? 'Workspace ' + summary.Extraction.OutputDir : 'Extraction completed' },
      { label: 'Filesystems', value: ensureArray(summary.FileSystems).length },
      { label: 'Config files', value: ensureArray(summary.Configs).length },
      { label: 'Services', value: ensureArray(summary.Services).length },
      { label: 'Secrets', value: secrets.length, hint: secretEntropy > 0 ? 'Max entropy ' + secretEntropy.toFixed(2) : undefined },
      { label: 'Binaries', value: binaries.length, hint: binaryStats.nxDisabled > 0 ? binaryStats.nxDisabled + ' without NX' : undefined },
      { label: 'Binary CVEs', value: vulnTotal },
      { label: 'Package CVEs', value: pkgVulnTotal },
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
        labels: ['NX Enabled', 'NX Disabled', 'PIE Enabled', 'PIE Disabled', 'RELRO Full', 'RELRO Partial', 'RELRO None'],
        datasets: [
          { label: 'Count', data: [stats.nxEnabled, stats.nxDisabled, stats.pieEnabled, stats.pieDisabled, stats.relroFull, stats.relroPartial, stats.relroNone], backgroundColor: ['#16a34a', '#ef4444', '#0ea5e9', '#f97316', '#6366f1', '#fbbf24', '#9ca3af'] }
        ]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: { y: { beginAtZero: true, ticks: { precision: 0 } } }
      }
    });
  };
  const renderPartitionChart = (partitions) => {
    const chartEl = document.getElementById('partition-chart');
    const emptyEl = document.getElementById('partition-chart-empty');
    if (!chartEl || !emptyEl) { return; }
    if (!partitions.length || typeof window.Chart === 'undefined') {
      chartEl.classList.add('hidden');
      emptyEl.classList.remove('hidden');
      return;
    }
    const sorted = [...partitions].filter(Boolean).sort((a, b) => (b.Size || 0) - (a.Size || 0));
    const top = sorted.slice(0, 6);
    const otherSize = sorted.slice(6).reduce((sum, item) => sum + (item.Size || 0), 0);
    if (otherSize > 0) {
      top.push({ Name: 'Other', Size: otherSize });
    }
    if (!top.length) {
      chartEl.classList.add('hidden');
      emptyEl.classList.remove('hidden');
      return;
    }
    emptyEl.classList.add('hidden');
    new window.Chart(chartEl.getContext('2d'), {
      type: 'doughnut',
      data: {
        labels: top.map((item) => item.Name || 'Partition'),
        datasets: [{ data: top.map((item) => item.Size || 0), backgroundColor: ['#6366f1', '#22d3ee', '#a855f7', '#f97316', '#14b8a6', '#facc15', '#60a5fa'] }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { position: 'bottom' } }
      }
    });
  };
  const renderSecretChart = (secrets) => {
    const chartEl = document.getElementById('secret-chart');
    const emptyEl = document.getElementById('secret-chart-empty');
    if (!chartEl || !emptyEl) { return; }
    if (!secrets.length || typeof window.Chart === 'undefined') {
      chartEl.classList.add('hidden');
      emptyEl.classList.remove('hidden');
      return;
    }
    const counts = new Map();
    secrets.forEach((sec) => {
      const rule = (sec && sec.Rule) ? String(sec.Rule) : 'Unknown';
      counts.set(rule, (counts.get(rule) || 0) + 1);
    });
    const entries = Array.from(counts.entries()).sort((a, b) => b[1] - a[1]);
    const top = entries.slice(0, 8);
    emptyEl.classList.add('hidden');
    new window.Chart(chartEl.getContext('2d'), {
      type: 'polarArea',
      data: {
        labels: top.map((entry) => entry[0]),
        datasets: [{ data: top.map((entry) => entry[1]), backgroundColor: ['#f472b6', '#38bdf8', '#facc15', '#94a3b8', '#f97316', '#a855f7', '#4ade80', '#f87171'] }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { position: 'bottom' } }
      }
    });
  };
  const renderSeverityChart = (binaryFindings, packageFindings) => {
    const chartEl = document.getElementById('severity-chart');
    const emptyEl = document.getElementById('severity-chart-empty');
    if (!chartEl || !emptyEl) { return; }
    const severities = ['critical', 'high', 'medium', 'low', 'info'];
    const counts = new Map(severities.map((sev) => [sev, 0]));
    const collect = (findings) => {
      ensureArray(findings).forEach((finding) => {
        ensureArray(finding && finding.CVEs).forEach((cve) => {
          const sev = String(cve && cve.Severity || '').toLowerCase();
          if (counts.has(sev)) {
            counts.set(sev, counts.get(sev) + 1);
          } else if (sev) {
            counts.set(sev, (counts.get(sev) || 0) + 1);
          }
        });
      });
    };
    collect(binaryFindings);
    collect(packageFindings);
    const total = Array.from(counts.values()).reduce((sum, value) => sum + value, 0);
    if (!total || typeof window.Chart === 'undefined') {
      chartEl.classList.add('hidden');
      emptyEl.classList.remove('hidden');
      return;
    }
    emptyEl.classList.add('hidden');
    const labels = Array.from(counts.keys());
    const data = labels.map((label) => counts.get(label));
    new window.Chart(chartEl.getContext('2d'), {
      type: 'doughnut',
      data: {
        labels: labels.map((label) => label.toUpperCase()),
        datasets: [{ data, backgroundColor: ['#ef4444', '#f97316', '#facc15', '#34d399', '#60a5fa'] }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { position: 'bottom' } }
      }
    });
  };
  const renderVenn = (configs, services, secrets) => {
    const container = document.getElementById('venn-chart');
    const empty = document.getElementById('venn-empty');
    if (!container || !empty) { return; }
    container.innerHTML = '';
    if (typeof window.venn === 'undefined' || typeof window.d3 === 'undefined') {
      empty.textContent = 'Interactive relationship map unavailable offline.';
      empty.classList.remove('hidden');
      return;
    }
    const configDirs = new Set(ensureArray(configs).map((cfg) => getDir(cfg && cfg.File)));
    const serviceDirs = new Set(ensureArray(services).map((svc) => getDir(svc && svc.Path)));
    const secretDirs = new Set(ensureArray(secrets).map((sec) => getDir(sec && sec.File)));
    const size = (set) => Array.from(set).filter(Boolean).length;
    const intersection = (sets) => {
      if (!sets.length) return new Set();
      const [first, ...rest] = sets;
      return new Set(Array.from(first).filter((item) => item && rest.every((set) => set.has(item))));
    };
    const configsOnly = size(configDirs);
    const servicesOnly = size(serviceDirs);
    const secretsOnly = size(secretDirs);
    const configService = intersection([configDirs, serviceDirs]);
    const configSecrets = intersection([configDirs, secretDirs]);
    const serviceSecrets = intersection([serviceDirs, secretDirs]);
    const allThree = intersection([configDirs, serviceDirs, secretDirs]);
    const vennData = [];
    if (configsOnly) vennData.push({ sets: ['Configs'], size: configsOnly });
    if (servicesOnly) vennData.push({ sets: ['Services'], size: servicesOnly });
    if (secretsOnly) vennData.push({ sets: ['Secrets'], size: secretsOnly });
    if (configService.size) vennData.push({ sets: ['Configs', 'Services'], size: configService.size });
    if (configSecrets.size) vennData.push({ sets: ['Configs', 'Secrets'], size: configSecrets.size });
    if (serviceSecrets.size) vennData.push({ sets: ['Services', 'Secrets'], size: serviceSecrets.size });
    if (allThree.size) vennData.push({ sets: ['Configs', 'Services', 'Secrets'], size: allThree.size });
    if (!vennData.length) {
      empty.classList.remove('hidden');
      return;
    }
    empty.classList.add('hidden');
    const diagram = window.venn.VennDiagram().width(container.clientWidth).height(320);
    window.d3.select(container).datum(vennData).call(diagram);
    window.d3.select(container).selectAll('text').style('font-family', 'Inter, sans-serif');
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
      return '<li><span class="badge badge-info">' + id + '</span> ' + badge + description + refHtml + '</li>';
    });
    return '<ul class="cve-list">' + items.join('') + '</ul>';
  };
  const partitions = ensureArray(summary.Extraction && summary.Extraction.Partitions).map((part) => ({
    name: part && part.Name ? escapeHTML(part.Name) : 'Artifact',
    type: part && part.Type ? escapeHTML(part.Type) : '-',
    size: formatBytes(part && part.Size),
    offset: part && part.Offset && part.Offset > 0 ? formatCount(part.Offset) : '-',
    entropy: (part && part.Entropy) ? part.Entropy.toFixed(2) : '-',
    compression: escapeHTML(part && part.Compression ? part.Compression : '-'),
    notes: escapeHTML(part && part.Notes ? part.Notes : '-'),
    path: '<code>' + escapeHTML(part && part.Path ? part.Path : '-') + '</code>',
    search: [part && part.Name, part && part.Path, part && part.Type].join(' ')
  }));
  renderTable('extraction-table', [
    { label: 'Artifact', field: 'name', isHTML: true, searchField: 'search' },
    { label: 'Type', field: 'type' },
    { label: 'Size', field: 'size' },
    { label: 'Offset', field: 'offset' },
    { label: 'Entropy', field: 'entropy' },
    { label: 'Compression', field: 'compression' },
    { label: 'Notes', field: 'notes', isHTML: true },
    { label: 'Location', field: 'path', isHTML: true }
  ], partitions);
  const filesystemRows = ensureArray(summary.FileSystems).map((fs) => ({
    image: '<code>' + escapeHTML(fs && fs.ImagePath ? fs.ImagePath : '-') + '</code>',
    type: text(fs && fs.Type),
    size: formatBytes(fs && fs.Size),
    offset: fs && fs.Offset && fs.Offset > 0 ? formatCount(fs.Offset) : '-',
    notes: escapeHTML(fs && fs.Notes ? fs.Notes : '-'),
    search: [fs && fs.ImagePath, fs && fs.Type, fs && fs.Notes].join(' ')
  }));
  renderTable('filesystem-table', [
    { label: 'Image', field: 'image', isHTML: true, searchField: 'search' },
    { label: 'Type', field: 'type' },
    { label: 'Size', field: 'size' },
    { label: 'Offset', field: 'offset' },
    { label: 'Notes', field: 'notes', isHTML: true }
  ], filesystemRows);
  const configRows = ensureArray(summary.Configs).map((cfg) => {
    const params = ensureArray(cfg && cfg.Params);
    const credentials = params.filter((p) => p && p.Credential).length;
    const example = params.length ? '<code>' + escapeHTML(params[0].Key || '') + '=' + escapeHTML(params[0].Value || '') + '</code>' : '<span class="muted">-</span>';
    return {
      file: '<code>' + escapeHTML(cfg && cfg.File || '-') + '</code>',
      format: text((cfg && cfg.Format || '').toUpperCase()),
      entries: formatCount(params.length),
      credentials: formatCount(credentials),
      example,
      search: [cfg && cfg.File, cfg && cfg.Format].join(' ')
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
    name: '<code>' + escapeHTML(svc && svc.Name || '-') + '</code>',
    type: text(svc && svc.Type),
    path: '<code>' + escapeHTML(svc && svc.Path || '-') + '</code>',
    provides: ensureArray(svc && svc.Provides).length ? escapeHTML(ensureArray(svc.Provides).join(', ')) : '<span class="muted">-</span>',
    search: [svc && svc.Name, svc && svc.Type, svc && svc.Path, ensureArray(svc && svc.Provides).join(' ')].join(' ')
  }));
  renderTable('service-table', [
    { label: 'Name', field: 'name', isHTML: true, searchField: 'search' },
    { label: 'Type', field: 'type' },
    { label: 'Path', field: 'path', isHTML: true },
    { label: 'Provides', field: 'provides', isHTML: true }
  ], serviceRows);
  const secretRows = ensureArray(summary.Secrets).map((sec) => ({
    file: '<code>' + escapeHTML(sec && sec.File || '-') + '</code>',
    line: formatCount(typeof (sec && sec.Line) === 'number' ? sec.Line : 0),
    rule: text(sec && sec.Rule),
    match: '<code>' + escapeHTML(sec && sec.Match || '-') + '</code>',
    entropy: typeof (sec && sec.Entropy) === 'number' ? sec.Entropy.toFixed(2) : '-',
    search: [sec && sec.File, sec && sec.Rule, sec && sec.Match].join(' ')
  }));
  renderTable('secret-table', [
    { label: 'File', field: 'file', isHTML: true, searchField: 'search' },
    { label: 'Line', field: 'line' },
    { label: 'Rule', field: 'rule' },
    { label: 'Match', field: 'match', isHTML: true },
    { label: 'Entropy', field: 'entropy' }
  ], secretRows);
  const binaryRows = ensureArray(summary.Binaries).map((bin) => ({
    path: '<code>' + escapeHTML(bin && bin.Path || '-') + '</code>',
    type: text(bin && bin.Type),
    arch: text(bin && bin.Architecture),
    relro: text((bin && bin.RELRO || '').toUpperCase()),
    nx: boolBadge(!!(bin && bin.NXEnabled)),
    pie: boolBadge(!!(bin && bin.PIEEnabled)),
    stripped: boolBadge(!!(bin && bin.Stripped)),
    interp: bin && bin.Interpreter ? '<code>' + escapeHTML(bin.Interpreter) + '</code>' : '<span class="muted">-</span>',
    search: [bin && bin.Path, bin && bin.Type, bin && bin.Architecture, bin && bin.Interpreter].join(' ')
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
    path: '<code>' + escapeHTML(vul && vul.Path || '-') + '</code>',
    hash: vul && vul.Hash ? '<code>' + escapeHTML(vul.Hash) + '</code>' : '<span class="muted">-</span>',
    cves: formatCVEList(vul && vul.CVEs),
    cveText: ensureArray(vul && vul.CVEs).map((cve) => [cve && cve.ID, cve && cve.Severity, ensureArray(cve && cve.References).join(' ')].join(' ')).join(' '),
    error: vul && vul.Error ? escapeHTML(vul.Error) : '<span class="muted">-</span>',
    search: [vul && vul.Path, vul && vul.Hash, vul && vul.Error].join(' ')
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
      pkg: '<code>' + escapeHTML(pkg && pkg.Name || '-') + '</code>',
      version: text(pkg && pkg.Version),
      source: text(pkg && pkg.Supplier),
      cves: formatCVEList(finding && finding.CVEs),
      cveText: ensureArray(finding && finding.CVEs).map((cve) => [cve && cve.ID, cve && cve.Severity, ensureArray(cve && cve.References).join(' ')].join(' ')).join(' '),
      notes: finding && finding.Error ? escapeHTML(finding.Error) : '<span class="muted">-</span>',
      search: [pkg && pkg.Name, pkg && pkg.Version, pkg && pkg.Supplier, finding && finding.Error].join(' ')
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
    const findings = ensureArray(plugin && plugin.Findings);
    const example = findings.length ? escapeHTML((findings[0].Severity ? findings[0].Severity.toUpperCase() + ': ' : '') + (findings[0].Summary || '')) : '-';
    return {
      plugin: text(plugin && plugin.Plugin),
      findings: formatCount(findings.length),
      example,
      search: [plugin && plugin.Plugin, findings.map((f) => f.Summary).join(' ')].join(' ')
    };
  });
  renderTable('plugin-table', [
    { label: 'Plugin', field: 'plugin', searchField: 'search' },
    { label: 'Findings', field: 'findings' },
    { label: 'Example', field: 'example' }
  ], pluginRows);
  const artefactContainer = document.getElementById('artefact-list');
  if (artefactContainer) {
    artefactContainer.innerHTML = '';
    const list = document.createElement('ul');
    list.className = 'artefact-list';
    const addArtefact = (label, value) => {
      const item = document.createElement('li');
      const spanLabel = document.createElement('span');
      spanLabel.className = 'label';
      spanLabel.textContent = label;
      const spanValue = document.createElement('span');
      spanValue.innerHTML = '<code>' + escapeHTML(value || '-') + '</code>';
      item.appendChild(spanLabel);
      item.appendChild(spanValue);
      list.appendChild(item);
    };
    ensureArray(summary.SBOMPaths).forEach((path) => addArtefact('SBOM', path));
    if (summary.SBOM && summary.SBOM.Format) {
      addArtefact('SBOM format', summary.SBOM.Format);
    }
    ensureArray(summary.SBOMSignatures).forEach((sig) => addArtefact('SBOM signature', sig));
    addArtefact('Markdown report', 'report.md');
    addArtefact('JSON report', 'report.json');
    artefactContainer.appendChild(list);
  }
  const sbomMeta = document.getElementById('sbom-meta');
  if (sbomMeta) {
    const sbomCount = ensureArray(summary.SBOMPaths).length || (summary.SBOM ? 1 : 0);
    sbomMeta.textContent = sbomCount ? 'SBOM artefacts generated: ' + sbomCount + '. Use them for dependency tracking or SBOM ingestion pipelines.' : 'No SBOM artefacts were produced.';
  }
  renderCards(summary);
  renderBinaryChart(ensureArray(summary.Binaries));
  renderPartitionChart(ensureArray(summary.Extraction && summary.Extraction.Partitions));
  renderSecretChart(ensureArray(summary.Secrets));
  renderSeverityChart(ensureArray(summary.Vulnerable), ensureArray(summary.PackageVulns));
  renderVenn(ensureArray(summary.Configs), ensureArray(summary.Services), ensureArray(summary.Secrets));
  const pdfButton = document.getElementById('pdf-button');
  if (pdfButton) {
    const firmwareName = (summary.Firmware || 'firmware').split(/[\\/]/).pop().replace(/[^a-z0-9\-_.]+/gi, '_');
    pdfButton.addEventListener('click', () => {
      if (typeof window.html2pdf === 'undefined') {
        pdfButton.textContent = 'PDF not available offline';
        pdfButton.disabled = true;
        return;
      }
      pdfButton.disabled = true;
      const originalText = pdfButton.textContent;
      pdfButton.textContent = 'Preparing PDF...';
      window.html2pdf().set({ filename: firmwareName + '_report.pdf', margin: 10, image: { type: 'jpeg', quality: 0.98 }, html2canvas: { scale: 2 }, jsPDF: { unit: 'mm', format: 'a4', orientation: 'portrait' } }).from(document.body).save().catch((err) => {
        console.error('PDF export failed', err);
        pdfButton.textContent = 'PDF failed';
      }).finally(() => {
        setTimeout(() => {
          pdfButton.disabled = false;
          pdfButton.textContent = originalText;
        }, 800);
      });
    });
  }
})();
</script>
</body>
</html>`
