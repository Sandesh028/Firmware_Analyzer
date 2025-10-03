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
- SBOM generation (SPDX JSON, SPDX tag-value, or CycloneDX) with optional
  Ed25519 signing for downstream tooling
- Plugin execution framework for custom checks written in any language
- Optional online CVE enrichment via OSV/NVD with caching and rate limiting
- Firmware-to-firmware diff reports in Markdown and JSON for regression triage
- Web dashboard for browsing stored analyses and on-demand diff comparisons
- Batch scheduler capable of dispatching analyses locally or over SSH

## Prerequisites

- **Go 1.22 or later** – required to build the analyzer (`go env GOVERSION`).
- **Git** – to clone this repository.
- **Optional extractors** – `unblob` and `binwalk` are used when available to
  handle complex firmware containers:

  ```bash
  # Ubuntu / Debian
  sudo apt-get update && sudo apt-get install binwalk

  # macOS (Homebrew)
  brew install binwalk

  # Install unblob via pipx
  pipx install unblob
  ```

- **Common archive utilities** – ensure `tar`, `gzip`, and `zip` are present on
  the system (installed by default on most Linux/macOS distributions).

## Installation

Clone the repository and build the analyzer binary:

```bash
git clone https://github.com/Sandesh028/Firmware_Analyzer.git
cd Firmware_Analyzer
go build ./cmd/analyzer
```

To install the analyzer into your `$GOBIN` for repeated use (including the
dashboard, scheduler, and vulnerability feed helper), run:

```bash
go install ./cmd/analyzer ./cmd/dashboard ./cmd/scheduler ./cmd/vulndbupdate
```

Run the test suite to verify your environment:

```bash
go test ./...
```

## Usage

```bash
go run ./cmd/analyzer --fw /path/to/firmware.bin --out /tmp/report \
  --report-formats markdown,json \
  --vuln-db /path/to/vuln-db.json \
  --sbom-format spdx-json,spdx-tag-value \
  --sbom-sign-key ./keys/ed25519.pem \
  --enable-osv --enable-nvd --vuln-cache-dir /tmp/cache \
  --plugin-dir ./plugins
```

The analyzer writes the extracted workspace and generated artefacts inside the
specified output directory. When `--out` is omitted a temporary workspace is
created alongside the extracted firmware.

### Command reference

- `--fw` – path to the firmware image (required).
- `--out` – directory where extraction and reports are written. If omitted a
  temporary directory is used.
- `--report-formats` – comma separated list selecting `markdown`, `html`, and/or
  `json` outputs.
- `--vuln-db` – comma separated list of offline CVE database files. Each file
  should map SHA-256 hashes to CVE arrays. When omitted the analyzer falls back
  to the curated database bundled at build time.
- `--sbom-format` – comma separated SBOM formats (`spdx-json`, `spdx-tag-value`,
  `cyclonedx`, or `none`).
- `--sbom-sign-key` – path to an Ed25519 private key in PEM format used to sign
  generated SBOM artefacts (produces `.sig` files alongside each SBOM).
- `--baseline-report` – path to a previous `report.json` used for diffing the
  current analysis against a baseline.
- `--diff-formats` – comma separated diff artefact formats (`markdown`, `json`).
- `--history-dir` – directory where run metadata is stored for the dashboard.
- `--plugin-dir` – directory containing executable plugins. Plugins receive the
  analysis metadata as JSON on stdin together with `ANALYZER_ROOT` and
  `ANALYZER_METADATA_FORMAT=json` environment variables.
- `--enable-osv` / `--osv-endpoint` – enable and optionally override the OSV
  API endpoint for online CVE enrichment.
- `--enable-nvd` / `--nvd-endpoint` / `--nvd-api-key` – enable NVD lookups,
  override the endpoint, and provide an API key when required by rate limits.
- `--vuln-cache-dir` – directory where online lookup responses are cached to
  avoid duplicate API calls across runs.
- `--vuln-rate-limit` – maximum number of online vulnerability requests per
  minute (defaults to 30 when unset).

### Explore the tool

- Generate all report formats plus signed SPDX JSON + tag-value SBOMs:

  ```bash
  ./analyzer --fw firmware.bin --out ./analysis \
    --report-formats markdown,html,json \
    --sbom-format spdx-json,spdx-tag-value \
    --sbom-sign-key ./keys/ed25519.pem
  ```

- Run with an offline vulnerability feed and a custom plugin suite:

  ```bash
  ./analyzer --fw firmware.bin --out ./analysis --vuln-db ./feeds/openwrt.json --plugin-dir ./plugins
  ```

- Compare a new firmware against a previous report and enable online CVE
  lookups with caching:

  ```bash
  ./analyzer --fw firmware-new.bin --out ./analysis \
    --baseline-report ./previous/report.json --diff-formats markdown,json \
    --enable-osv --enable-nvd --vuln-cache-dir ~/.cache/analyzer-cves
  ```

- Quickly triage a sample firmware using the Go toolchain without installing a
  binary:

  ```bash
  go run ./cmd/analyzer --fw tests/fixtures/sample.bin --report-formats markdown
  ```

### Dashboard server

- Persist history alongside reports by setting `--history-dir` (defaults to
  `<out>/history` when `--out` is provided):

  ```bash
  ./analyzer --fw firmware.bin --out ./analysis --history-dir ./analysis/history
  ```

- Launch the dashboard to browse stored runs and request diffs on demand:

  ```bash
  ./dashboard --history-dir ./analysis/history --listen :8080
  ```

  Open `http://localhost:8080` in a browser to inspect the table of analyses,
  drill into summaries, and diff any two runs.

### Batch scheduler

- Prepare a JSON plan with one or more jobs:

  ```json
  {
    "jobs": [
      {
        "id": "release-rc1",
        "firmware": "images/fw-rc1.bin",
        "output_dir": "runs/rc1",
        "history_dir": "history",
        "report_formats": ["markdown", "json"]
      },
      {
        "id": "release-rc2",
        "firmware": "images/fw-rc2.bin",
        "output_dir": "runs/rc2",
        "remote_host": "edge-lab",
        "extra_args": ["--enable-osv"]
      }
    ]
  }
  ```

- Define optional remote hosts (SSH targets must have access to the firmware
  path and analyzer binary):

  ```bash
  ./scheduler --plan jobs.json \
    --history-dir history \
    --remote-host edge-lab=user@edge-host,analyzer=/usr/local/bin/analyzer
  ```

  Scheduler progress is streamed to stdout, and results populate the shared
  history directory for the dashboard.

### Curated vulnerability database

- A maintained baseline is shipped in `pkg/vuln/data/curated.json` and embedded into
  the analyzer binary so vulnerability lookups work out of the box.
- Refresh the curated feed at release time by merging upstream sources with the
  helper CLI:

  ```bash
  go run ./cmd/vulndbupdate --source feeds/openwrt.json --source feeds/vendor.json --out pkg/vuln/data/curated.json
  ```

- To fetch feeds over plain HTTP, add `--insecure-http` explicitly.

## Development

Run the full test suite before submitting changes:

```bash
go test ./...
```
