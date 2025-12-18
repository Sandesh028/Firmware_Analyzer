package tests

import (
	"os"
	"strings"
	"testing"

	"firmwareanalyzer/pkg/configparser"
	"firmwareanalyzer/pkg/diff"
	"firmwareanalyzer/pkg/plugin"
	"firmwareanalyzer/pkg/report"
	"firmwareanalyzer/pkg/service"
	"firmwareanalyzer/pkg/vuln"
)

func TestDiffComputeHighlightsChanges(t *testing.T) {
	t.Parallel()

	current := report.Summary{
		Firmware: "new.bin",
		Services: []service.Service{{Name: "httpd", Type: "init", Path: "/etc/init.d/httpd"}},
		Configs: []configparser.Finding{{
			File:   "/etc/config/system",
			Params: []configparser.Parameter{{Key: "hostname", Value: "router"}},
		}},
	}
	baseline := report.Summary{Firmware: "old.bin"}

	result := diff.Compute(current, baseline)
	if len(result.Services.Added) != 1 || !strings.Contains(result.Services.Added[0], "httpd") {
		t.Fatalf("expected new service in diff, got %#v", result.Services)
	}
	if len(result.Configs.Added) != 1 {
		t.Fatalf("expected config addition, got %#v", result.Configs)
	}

	outDir := t.TempDir()
	paths, err := diff.WriteFiles(result, outDir, diff.Formats{Markdown: true, JSON: true})
	if err != nil {
		t.Fatalf("write diff: %v", err)
	}
	if _, err := os.Stat(paths.Markdown); err != nil {
		t.Fatalf("missing markdown diff: %v", err)
	}
	if _, err := os.Stat(paths.JSON); err != nil {
		t.Fatalf("missing json diff: %v", err)
	}
	data, err := os.ReadFile(paths.Markdown)
	if err != nil {
		t.Fatalf("read markdown: %v", err)
	}
	if !strings.Contains(string(data), "Firmware Analysis Diff") {
		t.Fatalf("diff markdown missing heading")
	}
}

func TestDiffCoversVulnerabilitiesAndPlugins(t *testing.T) {
	t.Parallel()

	current := report.Summary{
		Vulnerable: []vuln.Finding{
			{
				Path: "/bin/httpd",
				CVEs: []vuln.CVE{{ID: "CVE-2024-0001"}, {ID: "CVE-2023-9999"}},
			},
			{
				Path: "/bin/new",
				CVEs: []vuln.CVE{{ID: "CVE-2025-1111"}},
			},
		},
		Plugins: []plugin.Result{
			{
				Plugin: "custom",
				Findings: []plugin.Finding{{
					Summary:  "Open debug interface",
					Severity: "high",
					Details:  map[string]any{"port": 31337},
				}},
			},
		},
	}

	baseline := report.Summary{
		Vulnerable: []vuln.Finding{
			{
				Path: "/bin/httpd",
				CVEs: []vuln.CVE{{ID: "CVE-2024-0001"}},
			},
			{
				Path: "/bin/old",
				CVEs: []vuln.CVE{{ID: "CVE-2020-0001"}},
			},
		},
		Plugins: []plugin.Result{
			{
				Plugin: "custom",
				Findings: []plugin.Finding{{
					Summary:  "Legacy shell access",
					Severity: "medium",
				}},
			},
		},
	}

	result := diff.Compute(current, baseline)

	if len(result.Vulnerabilities.Added) != 1 {
		t.Fatalf("expected new vulnerability entry, got %#v", result.Vulnerabilities)
	}
	if len(result.Vulnerabilities.Modified) != 1 {
		t.Fatalf("expected modified vulnerability entry, got %#v", result.Vulnerabilities)
	}
	if len(result.Vulnerabilities.Removed) != 1 {
		t.Fatalf("expected removed vulnerability entry, got %#v", result.Vulnerabilities)
	}

	if len(result.Plugins.Added) != 1 {
		t.Fatalf("expected new plugin finding, got %#v", result.Plugins)
	}
	if len(result.Plugins.Removed) != 1 {
		t.Fatalf("expected removed plugin finding, got %#v", result.Plugins)
	}
}
