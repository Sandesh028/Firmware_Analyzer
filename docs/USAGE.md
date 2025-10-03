# Usage Guide

The Drone Firmware Analyzer command line interface orchestrates firmware
extraction and analysis modules. The minimal invocation requires the firmware
image path:

```bash
go run ./cmd/analyzer --fw firmware.tgz --out ./analysis \
  --report-formats markdown,json --sbom-format spdx
```

## Flags

- `--fw` (required): path to the firmware image archive or directory.
- `--out`: optional directory where the workspace and generated artefacts will
  be written. When omitted, a temporary directory under the system temp location
  is created automatically.
- `--report-formats`: comma separated list enabling `markdown`, `html`, and/or
  `json` report outputs. Defaults to all formats.
- `--vuln-db`: comma separated list of JSON files containing `sha256 -> CVE`
  mappings used to enrich binary inspection results.
- `--sbom-format`: choose `spdx`, `cyclonedx`, or `none` to control SBOM
  generation.
- `--plugin-dir`: directory containing executable scripts that emit JSON
  findings for custom checks.

## Output Structure

```
<output>/
├── workspace/       # normalised extraction root
│   ├── ...
    └── report/
        ├── report.md        # Markdown summary (if selected)
        ├── report.html      # HTML view (if selected)
        ├── report.json      # Structured JSON output (if selected)
        └── sbom.spdx.json   # SBOM artefact (format depends on flag)
```

If `--out` is not provided the report directory is written inside the extracted
workspace.

## Adding Custom Modules

The analyzer pipeline is intentionally modular. To integrate a new analysis
stage:

1. Create a package under `pkg/` exposing a Go API that accepts the extraction
   root path and returns structured findings.
2. Add unit tests under `tests/` using temporary fixtures to validate behaviour.
3. Wire the new package into `cmd/analyzer/main.go`, feeding the results into the
   `report.Summary` structure so they surface in the generated reports.
