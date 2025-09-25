# Roadmap

The current implementation focuses on core workflows suitable for rapid firmware
triage. The following milestones track planned enhancements:

## Short Term

- Add optional integration with external extraction tools (binwalk/unblob) when
  available on the host system.
- Expand filesystem detection to parse partition tables (MTD, GPT) and identify
  mounted rootfs directories more accurately.
- Improve configuration parsing coverage with YAML and proprietary formats
  commonly seen in drone ecosystems.

## Medium Term

- Introduce CVE enrichment by hashing binaries and querying vulnerability data
  sources.
- Generate SBOM artefacts (SPDX/CycloneDX) for firmware contents.
- Provide structured JSON output alongside Markdown/HTML for ingestion into
  other tooling.

## Long Term

- Implement a plugin framework so teams can drop-in custom checks without
  modifying the core.
- Offer a web dashboard for browsing analysis history and diffing firmware
  versions over time.
