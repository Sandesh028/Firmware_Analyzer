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

func (g *Generator) htmlFromMarkdown(md string) (string, error) {
	var buf bytes.Buffer
	renderer := goldmark.New(
		goldmark.WithExtensions(extension.GFM, extension.Table, extension.Strikethrough, extension.DefinitionList, extension.TaskList),
		goldmark.WithRendererOptions(html.WithHardWraps(), html.WithXHTML()),
	)
	if err := renderer.Convert([]byte(md), &buf); err != nil {
		return "", err
	}

	tmpl := `<html><head><meta charset="utf-8"><title>Drone Firmware Analyzer Report</title><style>
body { font-family: "Inter", "Segoe UI", sans-serif; margin: 2rem auto; max-width: 1080px; line-height: 1.55; color: #202124; background: #f5f7fb; }
main { background: #ffffff; padding: 2.5rem; border-radius: 16px; box-shadow: 0 12px 40px rgba(15, 23, 42, 0.12); }
h1, h2, h3, h4 { color: #0f172a; }
table { border-collapse: collapse; width: 100%; margin: 1.25rem 0; font-size: 0.95rem; }
th, td { border: 1px solid #cbd5f5; padding: 0.6rem 0.75rem; text-align: left; }
th { background-color: #eef2ff; font-weight: 600; }
tr:nth-child(even) td { background-color: #f8fafc; }
code { background: #f1f5f9; padding: 0.2rem 0.35rem; border-radius: 4px; font-family: "Fira Code", "SFMono-Regular", monospace; }
blockquote { border-left: 4px solid #6366f1; margin: 1.25rem 0; padding: 0.75rem 1rem; background: #f5f5ff; }
a { color: #3730a3; }
pre { background: #0f172a; color: #f8fafc; padding: 1rem; border-radius: 8px; overflow-x: auto; }
@media (max-width: 720px) { body { margin: 1rem; } main { padding: 1.5rem; } table { font-size: 0.85rem; } }
</style></head><body><main>{{.Body}}</main></body></html>`
	t, err := template.New("report").Parse(tmpl)
	if err != nil {
		return "", err
	}
	var builder strings.Builder
	data := struct {
		Body template.HTML
	}{Body: template.HTML(buf.String())}
	if err := t.Execute(&builder, data); err != nil {
		return "", err
	}
	return builder.String(), nil
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
