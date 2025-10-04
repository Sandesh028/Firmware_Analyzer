package diff

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"firmwareanalyzer/pkg/binaryinspector"
	"firmwareanalyzer/pkg/configparser"
	"firmwareanalyzer/pkg/filesystem"
	"firmwareanalyzer/pkg/plugin"
	"firmwareanalyzer/pkg/report"
	"firmwareanalyzer/pkg/secrets"
	"firmwareanalyzer/pkg/service"
	"firmwareanalyzer/pkg/vuln"
)

// CategoryDiff summarises changes for a particular analysis category.
type CategoryDiff struct {
	Added    []string `json:"added,omitempty"`
	Removed  []string `json:"removed,omitempty"`
	Modified []string `json:"modified,omitempty"`
}

// Result aggregates category-level diffs between two firmware reports.
type Result struct {
	FirmwareNew     string       `json:"firmware_new"`
	FirmwareBase    string       `json:"firmware_base"`
	FileSystems     CategoryDiff `json:"filesystems,omitempty"`
	Configs         CategoryDiff `json:"configs,omitempty"`
	Services        CategoryDiff `json:"services,omitempty"`
	Secrets         CategoryDiff `json:"secrets,omitempty"`
	Binaries        CategoryDiff `json:"binaries,omitempty"`
	Vulnerabilities CategoryDiff `json:"vulnerabilities,omitempty"`
	Plugins         CategoryDiff `json:"plugins,omitempty"`
}

// Formats specifies which diff artefacts should be written.
type Formats struct {
	Markdown bool
	JSON     bool
}

// DefaultFormats enables Markdown and JSON outputs.
var DefaultFormats = Formats{Markdown: true, JSON: true}

// Paths describes the artefacts produced by WriteFiles.
type Paths struct {
	Markdown string
	JSON     string
}

// Compute calculates the differences between the current summary and a
// baseline summary.
func Compute(current, baseline report.Summary) Result {
	result := Result{
		FirmwareNew:  current.Firmware,
		FirmwareBase: baseline.Firmware,
	}
	result.FileSystems = diffMaps(filesystemsToMap(current.FileSystems), filesystemsToMap(baseline.FileSystems))
	result.Configs = diffMaps(configsToMap(current.Configs), configsToMap(baseline.Configs))
	result.Services = diffMaps(servicesToMap(current.Services), servicesToMap(baseline.Services))
	result.Secrets = diffMaps(secretsToMap(current.Secrets), secretsToMap(baseline.Secrets))
	result.Binaries = diffMaps(binariesToMap(current.Binaries), binariesToMap(baseline.Binaries))
	result.Vulnerabilities = diffMaps(vulnsToMap(current.Vulnerable), vulnsToMap(baseline.Vulnerable))
	result.Plugins = diffMaps(pluginsToMap(current.Plugins), pluginsToMap(baseline.Plugins))
	return result
}

// Markdown renders a Markdown summary of the diff result.
func (r Result) Markdown() string {
	var builder strings.Builder
	builder.WriteString("# Firmware Analysis Diff\n\n")
	builder.WriteString(fmt.Sprintf("**New firmware:** %s\\n\\n", placeholder(r.FirmwareNew)))
	builder.WriteString(fmt.Sprintf("**Baseline firmware:** %s\\n\\n", placeholder(r.FirmwareBase)))

	var hasChanges bool
	if renderCategory(&builder, "Filesystems", r.FileSystems) {
		hasChanges = true
	}
	if renderCategory(&builder, "Configurations", r.Configs) {
		hasChanges = true
	}
	if renderCategory(&builder, "Services", r.Services) {
		hasChanges = true
	}
	if renderCategory(&builder, "Secrets", r.Secrets) {
		hasChanges = true
	}
	if renderCategory(&builder, "Binaries", r.Binaries) {
		hasChanges = true
	}
	if renderCategory(&builder, "Vulnerabilities", r.Vulnerabilities) {
		hasChanges = true
	}
	if renderCategory(&builder, "Plugin Findings", r.Plugins) {
		hasChanges = true
	}

	if !hasChanges {
		builder.WriteString("No differences detected.\n")
	}
	return builder.String()
}

// WriteFiles writes selected diff formats to disk.
func WriteFiles(result Result, outputDir string, formats Formats) (Paths, error) {
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return Paths{}, err
	}
	if !formats.Markdown && !formats.JSON {
		formats = DefaultFormats
	}
	var paths Paths
	if formats.Markdown {
		mdPath := filepath.Join(outputDir, "diff.md")
		if err := os.WriteFile(mdPath, []byte(result.Markdown()), 0o644); err != nil {
			return Paths{}, err
		}
		paths.Markdown = mdPath
	}
	if formats.JSON {
		data, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return Paths{}, err
		}
		jsonPath := filepath.Join(outputDir, "diff.json")
		if err := os.WriteFile(jsonPath, data, 0o644); err != nil {
			return Paths{}, err
		}
		paths.JSON = jsonPath
	}
	return paths, nil
}

func renderCategory(builder *strings.Builder, title string, diff CategoryDiff) bool {
	if len(diff.Added) == 0 && len(diff.Removed) == 0 && len(diff.Modified) == 0 {
		return false
	}
	builder.WriteString(fmt.Sprintf("## %s\n", title))
	if len(diff.Added) > 0 {
		builder.WriteString("### Added\n")
		for _, entry := range diff.Added {
			builder.WriteString(fmt.Sprintf("- %s\n", entry))
		}
		builder.WriteString("\n")
	}
	if len(diff.Removed) > 0 {
		builder.WriteString("### Removed\n")
		for _, entry := range diff.Removed {
			builder.WriteString(fmt.Sprintf("- %s\n", entry))
		}
		builder.WriteString("\n")
	}
	if len(diff.Modified) > 0 {
		builder.WriteString("### Modified\n")
		for _, entry := range diff.Modified {
			builder.WriteString(fmt.Sprintf("- %s\n", entry))
		}
		builder.WriteString("\n")
	}
	return true
}

func diffMaps(current, baseline map[string]string) CategoryDiff {
	diff := CategoryDiff{}
	for key, value := range current {
		if old, ok := baseline[key]; !ok {
			diff.Added = append(diff.Added, fmt.Sprintf("%s = %s", key, value))
		} else if old != value {
			diff.Modified = append(diff.Modified, fmt.Sprintf("%s: %s -> %s", key, old, value))
		}
	}
	for key, value := range baseline {
		if _, ok := current[key]; !ok {
			diff.Removed = append(diff.Removed, fmt.Sprintf("%s = %s", key, value))
		}
	}
	sort.Strings(diff.Added)
	sort.Strings(diff.Removed)
	sort.Strings(diff.Modified)
	return diff
}

func filesystemsToMap(mounts []filesystem.Mount) map[string]string {
	out := make(map[string]string, len(mounts))
	for _, m := range mounts {
		details := fmt.Sprintf("%s size=%d offset=%d", placeholder(m.Type), m.Size, m.Offset)
		if strings.TrimSpace(m.Notes) != "" {
			details += " notes=" + strings.TrimSpace(m.Notes)
		}
		out[placeholder(m.ImagePath)] = details
	}
	return out
}

func configsToMap(cfgs []configparser.Finding) map[string]string {
	out := make(map[string]string)
	for _, cfg := range cfgs {
		for _, param := range cfg.Params {
			key := fmt.Sprintf("%s (%s)", param.Key, cfg.File)
			value := param.Value
			if param.Credential {
				value += " [credential]"
			}
			out[key] = value
		}
	}
	return out
}

func servicesToMap(services []service.Service) map[string]string {
	out := make(map[string]string, len(services))
	for _, svc := range services {
		key := fmt.Sprintf("%s (%s)", svc.Name, svc.Type)
		value := strings.TrimSpace(svc.Path)
		if len(svc.Provides) > 0 {
			value += " provides=" + strings.Join(svc.Provides, ",")
		}
		out[key] = placeholder(value)
	}
	return out
}

func secretsToMap(secrets []secrets.Finding) map[string]string {
	out := make(map[string]string, len(secrets))
	for _, sec := range secrets {
		key := fmt.Sprintf("%s:%d (%s)", sec.File, sec.Line, sec.Rule)
		value := sec.Match
		if sec.Entropy > 0 {
			value += fmt.Sprintf(" entropy=%.2f", sec.Entropy)
		}
		out[key] = value
	}
	return out
}

func binariesToMap(binaries []binaryinspector.Result) map[string]string {
	out := make(map[string]string, len(binaries))
	for _, bin := range binaries {
		details := fmt.Sprintf("type=%s arch=%s relro=%s nx=%t pie=%t stripped=%t", placeholder(bin.Type), placeholder(bin.Architecture), strings.ToUpper(string(bin.RELRO)), bin.NXEnabled, bin.PIEEnabled, bin.Stripped)
		if bin.Interpreter != "" {
			details += " interp=" + bin.Interpreter
		}
		if bin.Err != "" {
			details += " error=" + bin.Err
		}
		out[placeholder(bin.Path)] = details
	}
	return out
}

func vulnsToMap(vulns []vuln.Finding) map[string]string {
	out := make(map[string]string, len(vulns))
	for _, finding := range vulns {
		ids := make([]string, 0, len(finding.CVEs))
		for _, cve := range finding.CVEs {
			if cve.ID != "" {
				ids = append(ids, cve.ID)
			}
		}
		sort.Strings(ids)
		value := strings.Join(ids, ",")
		if finding.Error != "" {
			if value != "" {
				value += " "
			}
			value += "error=" + finding.Error
		}
		out[placeholder(finding.Path)] = value
	}
	return out
}

func pluginsToMap(results []plugin.Result) map[string]string {
	out := make(map[string]string)
	for _, res := range results {
		if res.Error != "" {
			key := fmt.Sprintf("%s (error)", res.Plugin)
			out[key] = res.Error
		}
		for _, finding := range res.Findings {
			key := fmt.Sprintf("%s: %s", res.Plugin, finding.Summary)
			value := strings.TrimSpace(finding.Severity)
			if value == "" {
				value = "info"
			}
			if len(finding.Details) > 0 {
				keys := make([]string, 0, len(finding.Details))
				for k := range finding.Details {
					keys = append(keys, k)
				}
				sort.Strings(keys)
				var pairs []string
				for _, k := range keys {
					pairs = append(pairs, fmt.Sprintf("%s=%v", k, finding.Details[k]))
				}
				value += " " + strings.Join(pairs, ";")
			}
			out[key] = value
		}
	}
	return out
}

func placeholder(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return "-"
	}
	return trimmed
}
