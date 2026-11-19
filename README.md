# provenance-release

The reusable release-provenance workflow for Ribose software. One
versioned workflow; every consuming repository pins a commit SHA, never
a floating tag (the exemplar practice: a pinned SHA is the only
reference an auditor can re-verify).

## What it produces, per release

- `<artifact>.spdx.json` — an SPDX 3.0 (System Package Data Exchange)
  bill of materials.
- `<artifact>.cdx.json` — a CycloneDX 1.7 (ECMA-424) bill of materials.
  Both formats come from one dependency graph; one tool emits both.
- `<artifact>.attestation*` — SLSA Build Level 3 provenance, keylessly
  signed through Sigstore, verifiable with
  `gh attestation verify <artifact> -R <repo>`.
- NOTICE/ATTRIBUTION — the license and copyright notices the shipped
  licenses require, generated rather than hand-maintained.
- The declared support period for the release stream, stamped into the
  release metadata (the CRA Article 14 field, answered in advance).

Every SBOM is validated against the CISA 2026 Minimum Elements before
it attaches to the release. A validation failure fails the release.

## Consumption

```yaml
jobs:
  provenance:
    uses: riboseinc/provenance-release/.github/workflows/release.yml@<commit-sha>
    with:
      artifacts: dist/
      support-until: "2031-11-18"
```

## Policy

The normative document (formats, minimum elements, tiers, the supplier
identity and PURL conventions) lives at
`riboseinc/provenance` and renders at provenance.ribose.com.

## License

BSD-3-Clause. See [LICENSE](LICENSE).
