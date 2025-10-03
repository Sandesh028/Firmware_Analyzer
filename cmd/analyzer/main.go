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
	"firmwareanalyzer/pkg/plugin"
	"firmwareanalyzer/pkg/report"
	"firmwareanalyzer/pkg/sbom"
	"firmwareanalyzer/pkg/secrets"
	"firmwareanalyzer/pkg/service"
	"firmwareanalyzer/pkg/vuln"
)

func main() {
	firmwarePath := flag.String("fw", "", "path to the firmware image")
	outputDir := flag.String("out", "", "directory for reports and working files")
	formatFlag := flag.String("report-formats", "markdown,html,json", "comma-separated list of report formats (markdown, html, json)")
	vulnDBFlag := flag.String("vuln-db", "", "comma-separated list of CVE database files")
	sbomFormatFlag := flag.String("sbom-format", "spdx", "SBOM output format (spdx, cyclonedx, none)")
	pluginDirFlag := flag.String("plugin-dir", "", "directory containing analyzer plugins")
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

	vulnEnricher := vuln.NewEnricher(logger, vuln.Options{DatabasePaths: parseList(*vulnDBFlag)})
	vulnerabilityFindings, err := vulnEnricher.Enrich(ctx, binaries)
	if err != nil {
		logger.Printf("vulnerability enrichment error: %v", err)
	}

	sbomFormat, err := parseSBOMFormat(*sbomFormatFlag)
	if err != nil {
		log.Fatalf("invalid sbom format: %v", err)
	}

	pluginRunner := plugin.NewRunner(logger, plugin.Options{Directory: *pluginDirFlag})
	pluginResults, err := pluginRunner.Run(ctx, analysisRoot)
	if err != nil {
		logger.Printf("plugin execution error: %v", err)
	}

	summary := report.Summary{
		Firmware:    *firmwarePath,
		Extraction:  extraction,
		FileSystems: mounts,
		Configs:     configs,
		Services:    services,
		Secrets:     secretFindings,
		Binaries:    binaries,
		Vulnerable:  vulnerabilityFindings,
		Plugins:     pluginResults,
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

	if sbomFormat != "" {
		sbomGenerator := sbom.NewGenerator(logger, sbom.Options{Format: sbomFormat, ProductName: filepath.Base(*firmwarePath)})
		doc, err := sbomGenerator.Generate(ctx, analysisRoot, binaries)
		if err != nil {
			logger.Printf("sbom generation error: %v", err)
		} else {
			sbomPath := filepath.Join(outDir, fmt.Sprintf("sbom.%s.json", sbomFormat))
			if err := sbom.WriteJSON(doc, sbomPath); err != nil {
				logger.Printf("sbom write error: %v", err)
			} else {
				summary.SBOM = &doc
				summary.SBOMPath = sbomPath
			}
		}
	}

	paths, err := generator.WriteFiles(summary, outDir, formats)
	if err != nil {
		log.Fatalf("write report: %v", err)
	}

	logger.Printf("reports written (md=%s html=%s json=%s)", paths.Markdown, paths.HTML, paths.JSON)
	if summary.SBOMPath != "" {
		logger.Printf("sbom written %s", summary.SBOMPath)
	}
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

func parseList(value string) []string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return nil
	}
	tokens := strings.Split(trimmed, ",")
	var out []string
	for _, token := range tokens {
		t := strings.TrimSpace(token)
		if t == "" {
			continue
		}
		out = append(out, t)
	}
	return out
}

func parseSBOMFormat(value string) (sbom.Format, error) {
	trimmed := strings.TrimSpace(strings.ToLower(value))
	switch trimmed {
	case "", "spdx":
		return sbom.FormatSPDX, nil
	case "cyclonedx", "cdx":
		return sbom.FormatCycloneDX, nil
	case "none":
		return "", nil
	default:
		return "", fmt.Errorf("unknown sbom format %q", value)
	}
}
