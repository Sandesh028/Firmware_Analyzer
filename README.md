# Drone Firmware Analyzer

Drone Firmware Analyzer is a modular Go toolkit for extracting and auditing
firmware images from small IoT and drone platforms. It emphasises quick
analysis workflows by combining light-weight extraction, configuration parsing,
service discovery, secrets scanning, and ELF hardening inspection into a single
CLI entrypoint.

## Features

- Firmware extraction with built-in support for tar/tgz/zip images, nested
  partition discovery, and workspace normalisation
- Filesystem probing for SquashFS, UBI, ext, GPT and MTD images without mounts
- Configuration parsing across JSON, XML, YAML, TOML and INI with credential
  heuristics
- Service detection for SysV/BUSYBOX init scripts and systemd units
- Regex and entropy based secrets scanning with allow-list support
- Binary hardening analysis with Markdown, HTML and JSON reporting
- CVE enrichment for inspected binaries using offline hash databases
- SBOM generation (SPDX or CycloneDX JSON) for downstream tooling
- Plugin execution framework for custom checks written in any language

## Usage

```bash
go run ./cmd/analyzer --fw /path/to/firmware.bin --out /tmp/report \
  --report-formats markdown,json \
  --vuln-db /path/to/vuln-db.json \
  --sbom-format spdx \
  --plugin-dir ./plugins
```

The analyzer writes the extracted workspace and generated artefacts inside the
specified output directory. When `--out` is omitted a temporary workspace is
created alongside the extracted firmware.

## Development

Run the full test suite before submitting changes:

```bash
go test ./...
```
