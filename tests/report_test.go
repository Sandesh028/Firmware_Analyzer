package tests

import (
	"strings"
	"testing"

	"firmwareanalyzer/pkg/binaryinspector"
	"firmwareanalyzer/pkg/extractor"
	"firmwareanalyzer/pkg/report"
)

func TestReportMarkdownContainsSections(t *testing.T) {
	summary := report.Summary{
		Firmware:   "sample.bin",
		Extraction: &extractor.Result{OutputDir: "/tmp/out"},
		Binaries:   []binaryinspector.Result{{Path: "/bin/app"}},
	}

	gen := report.NewGenerator(nil)
	md := gen.Markdown(summary)
	if md == "" {
		t.Fatalf("expected markdown output")
	}
	if !strings.Contains(md, "# Drone Firmware Analyzer Report") {
		t.Fatalf("missing heading: %s", md)
	}
}
