package main

import (
	"context"
	"flag"
	"log"
	"os"
	"path/filepath"
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

	generator := report.NewGenerator(logger)
	outDir := *outputDir
	if outDir == "" {
		outDir = filepath.Join(extraction.OutputDir, "report")
	}
	if _, _, err := generator.WriteFiles(summary, outDir); err != nil {
		log.Fatalf("write report: %v", err)
	}

	logger.Printf("analysis complete in %s", time.Since(start).Round(time.Millisecond))
}
