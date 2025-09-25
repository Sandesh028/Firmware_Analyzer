# Usage Guide

The Drone Firmware Analyzer command line interface orchestrates firmware
extraction and analysis modules. The minimal invocation requires the firmware
image path:

```bash
go run ./cmd/analyzer --fw firmware.tgz
```

## Flags

- `--fw` (required): path to the firmware image archive or directory.
- `--out`: optional directory where the workspace and generated reports will be
  written. When omitted, a temporary directory under the system temp location is
  created automatically.

## Output Structure

```
<output>/
├── workspace/       # normalised extraction root
│   ├── ...
└── report/
    ├── report.md    # Markdown summary
    └── report.html  # HTML view
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
