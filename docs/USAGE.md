# Usage Guide

The Drone Firmware Analyzer command line interface orchestrates firmware
extraction and analysis modules. The minimal invocation requires the firmware
image path:

```bash
go run ./cmd/analyzer --fw firmware.tgz --out ./analysis \
  --report-formats markdown,json \
  --sbom-format spdx-json,spdx-tag-value --sbom-sign-key ./keys/ed25519.pem \
  --enable-osv --enable-nvd --vuln-cache-dir ~/.cache/analyzer
```

## Flags

- `--fw` (required): path to the firmware image archive or directory.
- `--out`: optional directory where the workspace and generated artefacts will
  be written. When omitted, a temporary directory under the system temp location
  is created automatically.
- `--report-formats`: comma separated list enabling `markdown`, `html`, and/or
  `json` report outputs. Defaults to all formats.
- `--vuln-db`: comma separated list of JSON files containing `sha256 -> CVE`
  mappings used to enrich binary inspection results. When omitted, the embedded
  `pkg/vuln/data/curated.json` dataset is applied automatically.
- `--sbom-format`: comma separated SBOM formats (`spdx-json`, `spdx-tag-value`,
  `cyclonedx`, or `none`).
- `--sbom-sign-key`: optional Ed25519 private key (PEM) used to sign SBOM
  artefacts, emitting `.sig` companions.
- `--baseline-report`: previous `report.json` used for diff generation.
- `--diff-formats`: comma separated diff outputs (`markdown`, `json`).
- `--plugin-dir`: directory containing executable scripts that emit JSON
  findings for custom checks.
- `--enable-osv` / `--osv-endpoint`: enable OSV lookups and optionally override
  the API endpoint.
- `--enable-nvd` / `--nvd-endpoint` / `--nvd-api-key`: enable NVD lookups,
  change the endpoint, and supply an API key when required.
- `--vuln-cache-dir`: directory where online CVE responses are cached between
  runs.
- `--vuln-rate-limit`: maximum number of online CVE requests per minute.

## Output Structure

```
<output>/
├── workspace/       # normalised extraction root
│   ├── ...
    └── report/
        ├── report.md        # Markdown summary (if selected)
        ├── report.html      # HTML view (if selected)
        ├── report.json      # Structured JSON output (if selected)
        ├── sbom.spdx.json   # SBOM artefact(s) based on --sbom-format
        ├── sbom.spdx.sig    # Ed25519 signature(s) when --sbom-sign-key is set
        └── diff.md/json     # Optional diff reports when --baseline-report is supplied
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

## Maintaining the curated CVE bundle

Releases embed `pkg/vuln/data/curated.json` into the analyzer binary. Regenerate the
feed before shipping a release by merging upstream JSON feeds:

```bash
go run ./cmd/vulndbupdate --source feeds/openwrt.json --source feeds/vendor.json --out pkg/vuln/data/curated.json
```

The helper only allows HTTPS downloads by default. Use `--insecure-http` if a
source lacks TLS, and provide additional `--source` flags as required.
