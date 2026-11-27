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
- `<artifact>.openvex.json` — an OpenVEX statement set: valid and empty to
  start, growing curated "not affected" claims for known-noisy advisories.
- NOTICE/ATTRIBUTION — the license and copyright notices the shipped
  licenses require, generated rather than hand-maintained.
- `SHA256SUMS.txt` — a GNU `sha256sum` checksums file covering every shipped
  file. The checksums file is itself keylessly attested, so the whole release
  verifies with `gh attestation verify SHA256SUMS.txt -R <repo>`.
- The declared support period for the release stream, stamped into the
  release metadata (the CRA Article 14 field, answered in advance) and
  carried as the structured `provenance:support-until` property in both SBOM
  formats, machine-readable for CRA-style consumers.

Every SBOM is validated against the CISA 2026 Minimum Elements before
it attaches to the release. A validation failure fails the release.

## Consumption

```yaml
jobs:
  provenance:
    uses: riboseinc/provenance-release/.github/workflows/release.yml@<commit-sha>
    permissions:
      contents: write
      id-token: write
      attestations: write
    with:
      artifacts: dist/
      support-until: "2031-11-18"
```

### Inputs

- `artifacts` (required): Path to a built release artifact file or directory of artifacts.
- `support-until` (required): Declared support end date in `YYYY-MM-DD` format. The workflow writes this value to `lifecycle.json` and appends a support-period section idempotently to the GitHub Release notes.
- `artifact-name` (optional): GitHub Actions workflow artifact name to download into `artifacts` before scanning.
- `release-tag` (optional): GitHub Release tag to update. Defaults to `github.ref_name`.
- `author` (optional): SBOM author identity. Defaults to `github.repository_owner`.
- `supplier` (optional): Component supplier identity. Defaults to `author`.
- `attest` (optional, default `true`): Controls keyless SLSA Build Level 3 provenance generation through `actions/attest-build-provenance`. Private repositories skip attestation automatically with a notice under the Phase 1 exception.
- `upload-release` (optional, default `true`): Controls uploading `*.spdx.json`, `*.cdx.json`, `NOTICE`, and `lifecycle.json` to the GitHub Release and updating release notes.

## Local verification

Run the three required verification gates locally with Node.js 22 or newer:

```bash
npm ci
npm run typecheck
npm test
npm run build
```

`npm run build` compiles the TypeScript tooling, verifies that every GitHub Action and binary dependency is pinned to a full commit SHA or SHA-256 checksum, and runs an end-to-end provenance dry-run.

## Policy

The normative document (formats, minimum elements, tiers, the supplier
identity and PURL conventions) lives at
`riboseinc/provenance` and renders at provenance.ribose.com.

## License

BSD-3-Clause. See [LICENSE](LICENSE).
