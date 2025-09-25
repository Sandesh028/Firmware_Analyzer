# Drone Firmware Analyzer

Drone Firmware Analyzer is a modular Go toolkit for extracting and auditing
firmware images from small IoT and drone platforms. It emphasises quick
analysis workflows by combining light-weight extraction, configuration parsing,
service discovery, secrets scanning, and ELF hardening inspection into a single
CLI entrypoint.

## Features

- Firmware extraction with built-in support for tar/tgz/zip images and
  workspace normalisation
- Filesystem probing for SquashFS, UBI and ext files
- Configuration parsing across JSON, XML, TOML and INI with credential
  heuristics
- Service detection for SysV/BUSYBOX init scripts and systemd units
- Regex and entropy based secrets scanning with allow-list support
- Binary hardening analysis with Markdown/HTML reporting

## Usage

```bash
go run ./cmd/analyzer --fw /path/to/firmware.bin --out /tmp/report
```

The analyzer writes the extracted workspace and generated reports inside the
specified output directory. When `--out` is omitted a temporary workspace is
created alongside the extracted firmware.

## Development

Run the full test suite before submitting changes:

```bash
go test ./...
```
