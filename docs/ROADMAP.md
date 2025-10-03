# Roadmap

The current implementation focuses on core workflows suitable for rapid firmware
triage. The following milestones track planned enhancements:

## Short Term

- ✅ Ship a curated vulnerability database bundle and tooling to update it
  alongside releases (`pkg/vuln/data/curated.json` + `cmd/vulndbupdate`).
- Capture richer filesystem metadata (e.g. partition offsets and compression
  statistics) for SBOM annotations.
- Extend plugin execution with structured input (workspace metadata) and
  enforce resource limits per plugin.

## Medium Term

- Support additional SBOM formats (e.g. SPDX tag-value) and signing options.
- Integrate optional online CVE lookups (OSV, NVD) with caching and rate limiting.
- Emit diff reports to compare two firmware images across all analyzers.

## Long Term

- Offer a web dashboard for browsing analysis history and diffing firmware
  versions over time.
- Introduce a scheduler for batch analysis and remote execution targets.
