package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"firmwareanalyzer/pkg/binaryinspector"
	"firmwareanalyzer/pkg/configparser"
	"firmwareanalyzer/pkg/extractor"
	"firmwareanalyzer/pkg/filesystem"
	"firmwareanalyzer/pkg/report"
	"firmwareanalyzer/pkg/secrets"
	"firmwareanalyzer/pkg/service"
)

func main() {
	firmwarePath := flag.String("fw", "", "path to the firmware image")
	outputDir := flag.String("out", "", "directory for reports and working files")
	formatFlag := flag.String("report-formats", "markdown,html,json", "comma-separated list of report formats (markdown, html, json)")
	flag.Parse()

	if *firmwarePath == "" {
		log.Fatal("missing required --fw flag")
	}

	ctx := context.Background()
	logger := log.New(os.Stdout, "analyzer ", log.LstdFlags)
	start := time.Now()

	workDir := ""
	if *outputDir != "" {
		workDir = filepath.Join(*outputDir, "workspace")
	}

	ext := extractor.New(extractor.Options{WorkDir: workDir, PreserveTemp: true}, logger)
	extraction, err := ext.Extract(ctx, *firmwarePath)
	if err != nil {
		log.Fatalf("extraction failed: %v", err)
	}

	analysisRoot := extraction.OutputDir

	fsDetector := filesystem.NewDetector(logger)
	mounts, err := fsDetector.Detect(ctx, analysisRoot)
	if err != nil {
		logger.Printf("filesystem detection error: %v", err)
	}

	cfgParser := configparser.NewParser(logger)
	configs, err := cfgParser.Parse(ctx, analysisRoot)
	if err != nil {
		logger.Printf("config parsing error: %v", err)
	}

	svcDetector := service.NewDetector(logger)
	services, err := svcDetector.Detect(ctx, analysisRoot)
	if err != nil {
		logger.Printf("service detection error: %v", err)
	}

	secretScanner := secrets.NewScanner(logger, nil)
	secretFindings, err := secretScanner.Scan(ctx, analysisRoot)
	if err != nil {
		logger.Printf("secret scanning error: %v", err)
	}

	inspector := binaryinspector.NewInspector(logger)
	binaries, err := inspector.Inspect(ctx, analysisRoot)
	if err != nil {
		logger.Printf("binary inspection error: %v", err)
	}

	summary := report.Summary{
		Firmware:    *firmwarePath,
		Extraction:  extraction,
		FileSystems: mounts,
		Configs:     configs,
		Services:    services,
		Secrets:     secretFindings,
		Binaries:    binaries,
	}

	formats, err := parseReportFormats(*formatFlag)
	if err != nil {
		log.Fatalf("invalid report format: %v", err)
	}

	generator := report.NewGenerator(logger)
	outDir := *outputDir
	if outDir == "" {
		outDir = filepath.Join(extraction.OutputDir, "report")
	}
	paths, err := generator.WriteFiles(summary, outDir, formats)
	if err != nil {
		log.Fatalf("write report: %v", err)
	}

	logger.Printf("reports written (md=%s html=%s json=%s)", paths.Markdown, paths.HTML, paths.JSON)
	logger.Printf("analysis complete in %s", time.Since(start).Round(time.Millisecond))
}

func parseReportFormats(value string) (report.Formats, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return report.DefaultFormats, nil
	}
	var formats report.Formats
	tokens := strings.Split(trimmed, ",")
	for _, token := range tokens {
		t := strings.TrimSpace(strings.ToLower(token))
		if t == "" {
			continue
		}
		switch t {
		case "md", "markdown":
			formats.Markdown = true
		case "html":
			formats.HTML = true
		case "json":
			formats.JSON = true
		default:
			return report.Formats{}, fmt.Errorf("unknown report format %q", token)
		}
	}
	if !formats.Markdown && !formats.HTML && !formats.JSON {
		return report.Formats{}, fmt.Errorf("no valid report formats selected")
	}
	return formats, nil
}
