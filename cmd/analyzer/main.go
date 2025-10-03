package main

import (
	"context"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"firmwareanalyzer/pkg/binaryinspector"
	"firmwareanalyzer/pkg/configparser"
	"firmwareanalyzer/pkg/dashboard"
	"firmwareanalyzer/pkg/diff"
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
	sbomFormatFlag := flag.String("sbom-format", "spdx-json", "SBOM output formats (comma-separated: spdx-json, spdx-tag-value, cyclonedx, none)")
	sbomSignKey := flag.String("sbom-sign-key", "", "path to an Ed25519 private key for signing SBOM artefacts")
	pluginDirFlag := flag.String("plugin-dir", "", "directory containing analyzer plugins")
	baselineReport := flag.String("baseline-report", "", "path to a baseline JSON report for diff generation")
	diffFormatsFlag := flag.String("diff-formats", "markdown,json", "comma-separated diff report formats (markdown, json)")
	historyDirFlag := flag.String("history-dir", "", "directory for storing analysis history for the dashboard")
	enableOSV := flag.Bool("enable-osv", false, "query the OSV API for additional CVE data")
	osvEndpoint := flag.String("osv-endpoint", "https://api.osv.dev/v1/query", "override OSV API endpoint")
	enableNVD := flag.Bool("enable-nvd", false, "query the NVD API for additional CVE data")
	nvdEndpoint := flag.String("nvd-endpoint", "https://services.nvd.nist.gov/rest/json/cves/2.0", "override NVD API endpoint")
	nvdAPIKey := flag.String("nvd-api-key", "", "NVD API key used when performing online lookups")
	vulnCacheDir := flag.String("vuln-cache-dir", "", "directory for caching online CVE responses")
	vulnRateLimit := flag.Int("vuln-rate-limit", 30, "maximum online CVE requests per minute")
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

	vulnOpts := vuln.Options{
		DatabasePaths:      parseList(*vulnDBFlag),
		CacheDir:           *vulnCacheDir,
		RateLimitPerMinute: *vulnRateLimit,
	}
	if *enableOSV {
		vulnOpts.OSV.Enabled = true
		vulnOpts.OSV.Endpoint = *osvEndpoint
	}
	if *enableNVD {
		vulnOpts.NVD.Enabled = true
		vulnOpts.NVD.Endpoint = *nvdEndpoint
		vulnOpts.NVD.APIKey = *nvdAPIKey
	}
	vulnEnricher := vuln.NewEnricher(logger, vulnOpts)
	vulnerabilityFindings, err := vulnEnricher.Enrich(ctx, binaries)
	if err != nil {
		logger.Printf("vulnerability enrichment error: %v", err)
	}

	sbomFormats, err := parseSBOMFormats(*sbomFormatFlag)
	if err != nil {
		log.Fatalf("invalid sbom format: %v", err)
	}
	var sbomGenerator *sbom.Generator
	if len(sbomFormats) > 0 {
		sbomGenerator, err = sbom.NewGenerator(logger, sbom.Options{
			Formats:        sbomFormats,
			ProductName:    filepath.Base(*firmwarePath),
			SigningKeyPath: *sbomSignKey,
		})
		if err != nil {
			log.Fatalf("sbom signer: %v", err)
		}
	}

	pluginRunner := plugin.NewRunner(logger, plugin.Options{Directory: *pluginDirFlag})
	pluginResults, err := pluginRunner.Run(ctx, plugin.Metadata{
		Firmware:        *firmwarePath,
		Root:            analysisRoot,
		Partitions:      extraction.Partitions,
		FileSystems:     mounts,
		Configs:         configs,
		Services:        services,
		Secrets:         secretFindings,
		Binaries:        binaries,
		Vulnerabilities: vulnerabilityFindings,
	})
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

	if sbomGenerator != nil {
		if err := os.MkdirAll(outDir, 0o755); err != nil {
			logger.Printf("sbom output directory error: %v", err)
		} else {
			doc, err := sbomGenerator.Generate(ctx, analysisRoot, binaries, extraction.Partitions)
			if err != nil {
				logger.Printf("sbom generation error: %v", err)
			} else {
				for _, format := range sbomGenerator.Formats() {
					data, ext, err := sbom.Encode(doc, format)
					if err != nil {
						logger.Printf("sbom encode (%s) error: %v", format, err)
						continue
					}
					sbomPath := filepath.Join(outDir, fmt.Sprintf("sbom.%s", ext))
					if err := os.WriteFile(sbomPath, data, 0o644); err != nil {
						logger.Printf("sbom write error: %v", err)
						continue
					}
					summary.SBOM = &doc
					summary.SBOMPaths = append(summary.SBOMPaths, sbomPath)
					if summary.SBOMPath == "" {
						summary.SBOMPath = sbomPath
					}
					sig, err := sbomGenerator.Sign(data)
					if err != nil {
						logger.Printf("sbom signing error: %v", err)
						continue
					}
					if len(sig) > 0 {
						sigPath := sbomPath + ".sig"
						encoded := base64.StdEncoding.EncodeToString(sig)
						if err := os.WriteFile(sigPath, []byte(encoded), 0o600); err != nil {
							logger.Printf("sbom signature write error: %v", err)
						} else {
							summary.SBOMSignatures = append(summary.SBOMSignatures, sigPath)
						}
					}
				}
			}
		}
	}

	paths, err := generator.WriteFiles(summary, outDir, formats)
	if err != nil {
		log.Fatalf("write report: %v", err)
	}

	logger.Printf("reports written (md=%s html=%s json=%s)", paths.Markdown, paths.HTML, paths.JSON)
	if len(summary.SBOMPaths) > 0 {
		for _, p := range summary.SBOMPaths {
			logger.Printf("sbom written %s", p)
		}
	}
	if len(summary.SBOMSignatures) > 0 {
		for _, p := range summary.SBOMSignatures {
			logger.Printf("sbom signature %s", p)
		}
	}

	var diffPaths *diff.Paths
	if *baselineReport != "" {
		baseline, err := report.LoadJSON(*baselineReport)
		if err != nil {
			log.Fatalf("load baseline report: %v", err)
		}
		diffFormats, err := parseDiffFormats(*diffFormatsFlag)
		if err != nil {
			log.Fatalf("invalid diff format: %v", err)
		}
		diffResult := diff.Compute(summary, baseline)
		dp, err := diff.WriteFiles(diffResult, outDir, diffFormats)
		if err != nil {
			log.Fatalf("write diff report: %v", err)
		}
		diffPaths = &dp
		logger.Printf("diff report written (md=%s json=%s)", dp.Markdown, dp.JSON)
	}

	duration := time.Since(start)

	historyDir := strings.TrimSpace(*historyDirFlag)
	if historyDir == "" && outDir != "" {
		historyDir = filepath.Join(outDir, "history")
	}
	if historyDir != "" {
		store, err := dashboard.NewFileStore(historyDir, logger)
		if err != nil {
			logger.Printf("history store error: %v", err)
		} else {
			if _, err := store.Record(ctx, summary, paths, diffPaths, duration); err != nil {
				logger.Printf("history record error: %v", err)
			}
		}
	}

	if err := snapshotRun(logger, *firmwarePath, outDir, paths, summary.SBOMPaths, summary.SBOMSignatures, diffPaths); err != nil {
		logger.Printf("snapshot error: %v", err)
	}

	logger.Printf("analysis complete in %s", duration.Round(time.Millisecond))
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

func parseSBOMFormats(value string) ([]sbom.Format, error) {
	trimmed := strings.TrimSpace(strings.ToLower(value))
	if trimmed == "" {
		return []sbom.Format{sbom.FormatSPDXJSON}, nil
	}
	if trimmed == "none" {
		return nil, nil
	}
	tokens := strings.Split(trimmed, ",")
	var formats []sbom.Format
	for _, token := range tokens {
		t := strings.TrimSpace(token)
		switch t {
		case "spdx", "spdx-json":
			formats = append(formats, sbom.FormatSPDXJSON)
		case "spdx-tag-value", "spdx-tv", "tag-value":
			formats = append(formats, sbom.FormatSPDXTagValue)
		case "cyclonedx", "cdx":
			formats = append(formats, sbom.FormatCycloneDX)
		case "":
			continue
		default:
			return nil, fmt.Errorf("unknown sbom format %q", token)
		}
	}
	if len(formats) == 0 {
		return nil, fmt.Errorf("no SBOM formats selected")
	}
	return formats, nil
}

func parseDiffFormats(value string) (diff.Formats, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return diff.DefaultFormats, nil
	}
	var formats diff.Formats
	tokens := strings.Split(trimmed, ",")
	for _, token := range tokens {
		t := strings.TrimSpace(strings.ToLower(token))
		switch t {
		case "markdown", "md":
			formats.Markdown = true
		case "json":
			formats.JSON = true
		case "":
			continue
		default:
			return diff.Formats{}, fmt.Errorf("unknown diff format %q", token)
		}
	}
	if !formats.Markdown && !formats.JSON {
		return diff.Formats{}, fmt.Errorf("no diff formats selected")
	}
	return formats, nil
}

func snapshotRun(logger *log.Logger, firmwarePath, reportDir string, reportPaths report.Paths, sbomPaths, sbomSignatures []string, diffPaths *diff.Paths) error {
	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("determine working directory: %w", err)
	}
	name := sanitizeName(filepath.Base(firmwarePath))
	if name == "" {
		name = "firmware"
	}
	target := filepath.Join(cwd, fmt.Sprintf("FA_%s", name))
	snapshotDir, err := ensureUniqueDir(target)
	if err != nil {
		return fmt.Errorf("prepare snapshot directory: %w", err)
	}

	artefacts := collectArtefacts(reportPaths, sbomPaths, sbomSignatures, diffPaths)
	for _, path := range artefacts {
		if err := transferArtefact(path, snapshotDir); err != nil {
			logger.Printf("snapshot move %s: %v", path, err)
		}
	}

	if err := mirrorReportDirectory(reportDir, snapshotDir, artefacts); err != nil {
		logger.Printf("snapshot mirror %s: %v", reportDir, err)
	}

	if err := writeSnapshotMetadata(snapshotDir, firmwarePath, reportDir); err != nil {
		return err
	}
	logger.Printf("snapshot written %s", snapshotDir)
	return nil
}

func writeSnapshotMetadata(dir, firmwarePath, reportDir string) error {
	metadata := fmt.Sprintf("Firmware: %s\nReports directory: %s\nSnapshot created: %s\n", firmwarePath, reportDir, time.Now().Format(time.RFC3339))
	return os.WriteFile(filepath.Join(dir, "README.txt"), []byte(metadata), 0o644)
}

func ensureUniqueDir(base string) (string, error) {
	candidate := base
	if info, err := os.Stat(candidate); err == nil {
		if !info.IsDir() {
			return "", fmt.Errorf("path %s exists and is not a directory", candidate)
		}
		for idx := 1; ; idx++ {
			next := fmt.Sprintf("%s_%d", base, idx)
			if _, err := os.Stat(next); os.IsNotExist(err) {
				candidate = next
				break
			}
		}
	} else if !os.IsNotExist(err) {
		return "", err
	}
	if err := os.MkdirAll(candidate, 0o755); err != nil {
		return "", err
	}
	return candidate, nil
}

func sanitizeName(name string) string {
	cleaned := strings.TrimSpace(name)
	if cleaned == "" {
		return ""
	}
	replacer := strings.NewReplacer(" ", "_", "/", "_", "\\", "_")
	cleaned = replacer.Replace(cleaned)
	cleaned = strings.ReplaceAll(cleaned, "..", "_")
	return cleaned
}

func collectArtefacts(reportPaths report.Paths, sbomPaths, sbomSignatures []string, diffPaths *diff.Paths) []string {
	var paths []string
	add := func(p string) {
		if strings.TrimSpace(p) != "" {
			paths = append(paths, p)
		}
	}
	add(reportPaths.Markdown)
	add(reportPaths.HTML)
	add(reportPaths.JSON)
	for _, p := range sbomPaths {
		add(p)
	}
	for _, p := range sbomSignatures {
		add(p)
	}
	if diffPaths != nil {
		add(diffPaths.Markdown)
		add(diffPaths.JSON)
	}
	return dedupeStrings(paths)
}

func transferArtefact(src, dstDir string) error {
	if strings.TrimSpace(src) == "" {
		return nil
	}
	if err := os.MkdirAll(dstDir, 0o755); err != nil {
		return err
	}
	dst := filepath.Join(dstDir, filepath.Base(src))
	if err := os.Rename(src, dst); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if copyErr := copyFile(src, dst); copyErr != nil {
			return copyErr
		}
		if removeErr := os.Remove(src); removeErr != nil && !os.IsNotExist(removeErr) {
			return removeErr
		}
	}
	return nil
}

func mirrorReportDirectory(reportDir, snapshotDir string, artefacts []string) error {
	reportDir = strings.TrimSpace(reportDir)
	if reportDir == "" {
		return nil
	}
	info, err := os.Stat(reportDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if !info.IsDir() {
		return nil
	}
	skip := make(map[string]struct{}, len(artefacts))
	for _, a := range artefacts {
		if a == "" {
			continue
		}
		skip[filepath.Clean(a)] = struct{}{}
	}
	return filepath.WalkDir(reportDir, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == reportDir {
			return nil
		}
		if _, ok := skip[filepath.Clean(path)]; ok {
			return nil
		}
		rel, err := filepath.Rel(reportDir, path)
		if err != nil {
			return err
		}
		target := filepath.Join(snapshotDir, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		return copyFile(path, target)
	})
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	info, err := in.Stat()
	if err != nil {
		return err
	}

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, info.Mode())
	if err != nil {
		return err
	}
	defer out.Close()

	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Sync()
}

func dedupeStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	var result []string
	for _, v := range values {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		result = append(result, v)
	}
	return result
}
