import assert from "node:assert/strict";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { describe, it } from "node:test";
import type { CycloneDx17Document, Spdx3Document } from "../src/enrich.js";
import { runProvenancePipeline } from "../src/pipeline.js";
import type { LifecycleDocument } from "../src/types.js";

const REPO_ROOT = path.resolve(import.meta.dirname, "..", "..");

interface EcosystemCase {
  name: string;
  fixtureDir: string;
  expectedPackages: string[];
}

const ECOSYSTEM_CASES: EcosystemCase[] = [
  {
    name: "C/C++ (Conan lockfile)",
    fixtureDir: path.join(REPO_ROOT, "test", "fixtures", "cpp"),
    expectedPackages: ["botan", "json-c", "zlib"],
  },
  {
    name: "Ruby (Gemfile.lock)",
    fixtureDir: path.join(REPO_ROOT, "test", "fixtures", "ruby"),
    expectedPackages: ["nokogiri", "racc", "rexml"],
  },
  {
    name: "Rust (Cargo.lock)",
    fixtureDir: path.join(REPO_ROOT, "test", "fixtures", "rust"),
    expectedPackages: ["serde", "sha2"],
  },
  {
    name: "TypeScript (package-lock.json)",
    fixtureDir: path.join(REPO_ROOT, "test", "fixtures", "typescript"),
    expectedPackages: ["zod"],
  },
];

describe("Ecosystem end-to-end provenance pipeline (syft v1.57.2+)", () => {
  for (const eco of ECOSYSTEM_CASES) {
    it(`generates CISA 2026 valid SPDX 3.0 + CycloneDX 1.7, NOTICE, and lifecycle.json for ${eco.name}`, async () => {
      const outDir = await mkdtemp(
        path.join(os.tmpdir(), "provenance-fixture-"),
      );
      try {
        const result = await runProvenancePipeline({
          artifactsPath: eco.fixtureDir,
          outputDir: outDir,
          releaseTag: "v1.0.0",
          supportUntil: "2031-11-18",
          author: "Example Security Team",
          supplier: "Example Organization",
          repository: "example-org/example-project",
          attest: true,
          isPrivateRepo: false,
          repoRoot: REPO_ROOT,
        });

        assert.equal(result.artifacts.length, 1);
        const artifact = result.artifacts[0]!;
        assert.equal(artifact.spdxValidation.valid, true);
        assert.equal(artifact.spdxValidation.passed.length, 17);
        assert.equal(artifact.cdxValidation.valid, true);
        assert.equal(artifact.cdxValidation.passed.length, 17);

        const spdx = JSON.parse(
          await readFile(artifact.spdxPath, "utf8"),
        ) as Spdx3Document;
        const cdx = JSON.parse(
          await readFile(artifact.cdxPath, "utf8"),
        ) as CycloneDx17Document;
        const notice = await readFile(result.noticePath, "utf8");
        const lifecycle = JSON.parse(
          await readFile(result.lifecyclePath, "utf8"),
        ) as LifecycleDocument;

        assert.equal(cdx.bomFormat, "CycloneDX");
        assert.equal(cdx.specVersion, "1.7");

        const creationInfo = spdx["@graph"].find(
          (n) => n.type === "CreationInfo",
        );
        assert.ok(creationInfo?.specVersion?.startsWith("3.0"));

        const cdxNames = new Set((cdx.components ?? []).map((c) => c.name));
        const spdxNames = new Set(
          spdx["@graph"]
            .filter((n) => n.type === "software_Package")
            .map((n) => n.name),
        );

        for (const expectedPkg of eco.expectedPackages) {
          assert.ok(
            cdxNames.has(expectedPkg),
            `Expected "${expectedPkg}" in CycloneDX 1.7 components for ${eco.name}`,
          );
          assert.ok(
            spdxNames.has(expectedPkg),
            `Expected "${expectedPkg}" in SPDX 3.0 packages for ${eco.name}`,
          );
          assert.ok(
            notice.includes(`Component: ${expectedPkg}`),
            `Expected "${expectedPkg}" in NOTICE for ${eco.name}`,
          );
        }

        assert.equal(lifecycle.supportUntil, "2031-11-18");
        assert.equal(lifecycle.releaseTag, "v1.0.0");
        assert.equal(lifecycle.attestation.status, "attested");

        // Structured support-until is carried in both SBOM formats (machine-readable).
        const supportProp = (cdx.metadata.properties ?? []).find(
          (p) => p.name === "provenance:support-until",
        );
        assert.equal(supportProp?.value, "2031-11-18");
        const spdxSupport = spdx["@graph"].find(
          (n) =>
            n.type === "Annotation" &&
            n.statement === "provenance:support-until=2031-11-18",
        );
        assert.ok(
          spdxSupport,
          "SPDX 3.0 must carry the structured support-until annotation",
        );

        // OpenVEX and the attested-shape checksums file are emitted.
        const openvex = JSON.parse(
          await readFile(result.openvexPath, "utf8"),
        ) as { statements: unknown[] };
        assert.ok(Array.isArray(openvex.statements));
        const checksums = await readFile(result.checksumsPath, "utf8");
        assert.ok(checksums.includes("openvex.json"));
        assert.ok(checksums.includes("lifecycle.json"));
        assert.ok(checksums.includes("NOTICE"));
      } finally {
        await rm(outDir, { recursive: true, force: true });
      }
    });
  }
});
