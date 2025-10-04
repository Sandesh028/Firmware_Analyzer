# Design Overview

Drone Firmware Analyzer is structured as a collection of focused Go packages
coordinated by a thin CLI layer. Each package owns a single responsibility and
exposes testable APIs so that future modules (e.g. SBOM generation or CVE
matching) can be integrated without modifying the existing workflow heavily.

## Package Responsibilities

- `pkg/extractor` normalises firmware archives into a workspace directory and
  records partition metadata for downstream modules.
- `pkg/filesystem` performs signature-based identification of embedded
  filesystem images without needing privileged mounts.
- `pkg/configparser` flattens JSON, XML, YAML, TOML and INI configuration files
  into dot-notated key/value pairs that higher layers can consume.
- `pkg/service` inventories init scripts and unit files to provide visibility
  into boot-time services.
- `pkg/secrets` scans text content for credential material using regular
  expressions, Shannon entropy and optional allow-lists.
- `pkg/binaryinspector` analyses ELF binaries for hardening settings such as
  RELRO, NX and PIE and renders Markdown tables for reports.
- `pkg/vuln` hashes binaries, enriches them with CVE metadata from offline
  databases, and can query OSV/NVD feeds with caching and rate limiting.
- `pkg/sbom` produces SPDX JSON, SPDX tag-value, or CycloneDX documents and can
  sign artefacts with Ed25519 keys.
- `pkg/diff` compares a fresh analysis summary against a baseline report and
  renders Markdown/JSON change logs.
- `pkg/plugin` executes external scripts that emit JSON findings, enabling
  custom organisational checks without modifying the core.
- `pkg/report` composes module results into Markdown, HTML and JSON artefacts.
- `pkg/dashboard` persists analysis history and serves a lightweight web UI for
  browsing reports and diffing stored runs.
- `pkg/scheduler` coordinates batched analyses using worker pools and optional
  SSH targets while delegating execution to the analyzer CLI.
- `pkg/utils` hosts shared helpers for map flattening, entropy calculations and
  heuristic utilities.

## Workflow

1. **Extraction** – The CLI invokes the extractor to unpack the firmware image
   into a workspace, retaining metadata about detected partitions.
2. **Scanning** – Filesystem detection, configuration parsing, service
   discovery, secret scanning and binary inspection operate on the workspace in
   parallel-friendly fashion (currently sequenced within the CLI for clarity).
3. **Reporting & history** – The report generator aggregates module outputs into
   Markdown, HTML and JSON documents, while SBOM artefacts (optionally signed)
   and vulnerability data are persisted. When `--history-dir` is set the
   dashboard store snapshots each run so the standalone `cmd/dashboard` server
   can surface history and diff comparisons.
4. **Batch execution** – Teams with larger firmware portfolios can describe job
   plans and optional remote hosts for `cmd/scheduler`, which dispatches the CLI
   with consistent flags while recording results into the shared history store.

## Testing Strategy

Each package ships with focused unit tests using temporary directories and
small fixtures to keep the test suite fast and deterministic. The tests validate
both success paths and heuristic triggers (e.g. credential detection) to guard
against regressions.
