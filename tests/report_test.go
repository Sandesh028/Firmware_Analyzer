package tests

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"firmwareanalyzer/pkg/binaryinspector"
	"firmwareanalyzer/pkg/extractor"
	"firmwareanalyzer/pkg/filesystem"
	"firmwareanalyzer/pkg/plugin"
	"firmwareanalyzer/pkg/report"
	"firmwareanalyzer/pkg/sbom"
	"firmwareanalyzer/pkg/vuln"
)

func TestReportMarkdownContainsSections(t *testing.T) {
	summary := report.Summary{
		Firmware: "sample.bin",
		Extraction: &extractor.Result{
			OutputDir: "/tmp/out",
			Partitions: []extractor.Partition{{
				Name:        "rootfs.squashfs",
				Path:        "/tmp/out/rootfs.squashfs",
				Type:        "squashfs",
				Size:        1024,
				Offset:      4096,
				Notes:       "detected via extension",
				Entropy:     7.8,
				Compression: "high",
			}},
		},
		FileSystems: []filesystem.Mount{{
			ImagePath: "/tmp/out/rootfs.squashfs",
			Type:      "squashfs",
			Size:      1024,
			Offset:    0,
			Notes:     "magic matched",
		}},
		Binaries: []binaryinspector.Result{{Path: "/bin/app"}},
	}

	gen := report.NewGenerator(nil)
	md := gen.Markdown(summary)
	if md == "" {
		t.Fatalf("expected markdown output")
	}
	if !strings.Contains(md, "# Drone Firmware Analyzer Report") {
		t.Fatalf("missing heading: %s", md)
	}
	if !strings.Contains(md, "Compression") {
		t.Fatalf("expected compression column: %s", md)
	}
}

func TestReportWriteFilesHonoursFormats(t *testing.T) {
	t.Parallel()

	summary := report.Summary{
		Firmware: "sample.bin",
		Extraction: &extractor.Result{
			OutputDir: "/tmp/out",
		},
		SBOM: &sbom.Document{Format: sbom.FormatSPDX},
	}
	gen := report.NewGenerator(nil)
	outDir := t.TempDir()
	paths, err := gen.WriteFiles(summary, outDir, report.Formats{Markdown: true, JSON: true})
	if err != nil {
		t.Fatalf("write files: %v", err)
	}
	if paths.HTML != "" {
		t.Fatalf("expected html path to be empty when not requested, got %s", paths.HTML)
	}
	if _, err := os.Stat(paths.Markdown); err != nil {
		t.Fatalf("missing markdown file: %v", err)
	}
	if _, err := os.Stat(paths.JSON); err != nil {
		t.Fatalf("missing json file: %v", err)
	}
	data, err := os.ReadFile(paths.JSON)
	if err != nil {
		t.Fatalf("read json: %v", err)
	}
	if !strings.Contains(string(data), "sample.bin") {
		t.Fatalf("expected firmware name in json, got %s", string(data))
	}
	mdData, err := os.ReadFile(paths.Markdown)
	if err != nil {
		t.Fatalf("read markdown: %v", err)
	}
	if !strings.Contains(string(mdData), "Drone Firmware Analyzer Report") {
		t.Fatalf("markdown missing heading")
	}
	if filepath.Dir(paths.Markdown) != outDir {
		t.Fatalf("markdown path outside output dir")
	}
}

func TestReportIncludesVulnerabilitiesAndPlugins(t *testing.T) {
	summary := report.Summary{
		Firmware: "sample.bin",
		Vulnerable: []vuln.Finding{{
			Path: "bin/app",
			Hash: "abc",
			CVEs: []vuln.CVE{{ID: "CVE-2024-0001"}},
		}},
		Plugins: []plugin.Result{{
			Plugin: "custom",
			Findings: []plugin.Finding{{
				Summary:  "issue",
				Severity: "medium",
			}},
		}},
	}
	gen := report.NewGenerator(nil)
	md := gen.Markdown(summary)
	if !strings.Contains(md, "Vulnerabilities") {
		t.Fatalf("expected vulnerabilities section")
	}
	if !strings.Contains(md, "Plugin Findings") {
		t.Fatalf("expected plugin section")
	}
}

func TestReportLoadJSON(t *testing.T) {
	t.Parallel()

	summary := report.Summary{Firmware: "sample.bin"}
	gen := report.NewGenerator(nil)
	outDir := t.TempDir()
	paths, err := gen.WriteFiles(summary, outDir, report.Formats{JSON: true})
	if err != nil {
		t.Fatalf("write files: %v", err)
	}
	loaded, err := report.LoadJSON(paths.JSON)
	if err != nil {
		t.Fatalf("load json: %v", err)
	}
	if loaded.Firmware != "sample.bin" {
		t.Fatalf("unexpected firmware %s", loaded.Firmware)
	}
}
