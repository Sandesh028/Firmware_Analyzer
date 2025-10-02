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
- `pkg/configparser` flattens JSON, XML, TOML and INI configuration files into
  dot-notated key/value pairs that higher layers can consume.
- `pkg/service` inventories init scripts and unit files to provide visibility
  into boot-time services.
- `pkg/secrets` scans text content for credential material using regular
  expressions, Shannon entropy and optional allow-lists.
- `pkg/binaryinspector` analyses ELF binaries for hardening settings such as
  RELRO, NX and PIE and renders Markdown tables for reports.
- `pkg/report` composes module results into Markdown and HTML artefacts.
- `pkg/utils` hosts shared helpers for map flattening, entropy calculations and
  heuristic utilities.

## Workflow

1. **Extraction** – The CLI invokes the extractor to unpack the firmware image
   into a workspace, retaining metadata about detected partitions.
2. **Scanning** – Filesystem detection, configuration parsing, service
   discovery, secret scanning and binary inspection operate on the workspace in
   parallel-friendly fashion (currently sequenced within the CLI for clarity).
3. **Reporting** – The report generator aggregates module outputs into Markdown
   and HTML documents, preserving tabular data for further processing.

## Testing Strategy

Each package ships with focused unit tests using temporary directories and
small fixtures to keep the test suite fast and deterministic. The tests validate
both success paths and heuristic triggers (e.g. credential detection) to guard
against regressions.
