import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  enrichCycloneDx17,
  enrichSpdx3,
  type CycloneDx17Document,
  type Spdx3Document,
} from "../src/enrich.js";
import { CISA_2026_ELEMENTS, type EnrichContext } from "../src/types.js";
import { validateCycloneDx17, validateSpdx3 } from "../src/validate.js";

const BASE_CTX: EnrichContext = {
  artifactName: "sample-app",
  artifactVersion: "1.2.3",
  artifactSha256: "a".repeat(64),
  author: "Example Security Team",
  supplier: "Example Inc.",
  repository: "example-org/sample-app",
  supportUntil: "2031-11-18",
  generationContext: "build",
  sbomVersion: 1,
  toolName: "syft",
  toolVersion: "1.57.2",
  timestamp: "2026-11-23T05:00:00Z",
  signatureReference: "sigstore:slsa-build-l3:example-org/sample-app@v1.2.3",
};

function makeMinimalRawSpdx(): Spdx3Document {
  return {
    "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
    "@graph": [
      {
        "@id": "_:CreationInfo-1",
        type: "CreationInfo",
        created: "2026-11-23T05:00:00Z",
        specVersion: "3.0.1",
        createdBy: ["SPDXRef:Organization-1"],
        createdUsing: ["SPDXRef:Tool-1"],
      },
      {
        type: "Organization",
        spdxId: "SPDXRef:Organization-1",
        creationInfo: "_:CreationInfo-1",
        name: "Anchore, Inc",
      },
      {
        type: "Tool",
        spdxId: "SPDXRef:Tool-1",
        creationInfo: "_:CreationInfo-1",
        name: "syft-1.57.2",
      },
      {
        type: "software_Package",
        spdxId: "SPDXRef:DocumentRoot-sample-app",
        creationInfo: "_:CreationInfo-1",
        name: "sample-app",
      },
      {
        type: "software_Package",
        spdxId: "SPDXRef:Package-dep-1",
        creationInfo: "_:CreationInfo-1",
        name: "dep-one",
        software_packageVersion: "2.0.0",
        software_packageUrl: "pkg:cargo/dep-one@2.0.0",
      },
      {
        type: "software_Sbom",
        spdxId: "SPDXRef:SBOM-1",
        creationInfo: "_:CreationInfo-1",
        rootElement: ["SPDXRef:DocumentRoot-sample-app"],
        element: [
          "SPDXRef:DocumentRoot-sample-app",
          "SPDXRef:Package-dep-1",
        ],
      },
      {
        type: "SpdxDocument",
        spdxId: "https://example.invalid/spdx/sample-app",
        creationInfo: "_:CreationInfo-1",
        name: "sample-app",
        rootElement: ["SPDXRef:SBOM-1"],
      },
    ],
  };
}

function makeMinimalRawCdx(): CycloneDx17Document {
  return {
    $schema: "http://cyclonedx.org/schema/bom-1.7.schema.json",
    bomFormat: "CycloneDX",
    specVersion: "1.7",
    version: 1,
    metadata: {
      timestamp: "2026-11-23T05:00:00Z",
      tools: {
        components: [
          {
            type: "application",
            author: "anchore",
            name: "syft",
            version: "1.57.2",
          },
        ],
      },
      component: {
        "bom-ref": "root-ref",
        type: "application",
        name: "sample-app",
        version: "1.2.3",
      },
    },
    components: [
      {
        "bom-ref": "pkg:cargo/dep-one@2.0.0",
        type: "library",
        name: "dep-one",
        version: "2.0.0",
        purl: "pkg:cargo/dep-one@2.0.0",
      },
    ],
    dependencies: [
      {
        ref: "root-ref",
        dependsOn: ["pkg:cargo/dep-one@2.0.0"],
      },
    ],
  };
}

describe("CISA 2026 Minimum Elements validator", () => {
  it("passes all 17 elements for an enriched SPDX 3.0 document", () => {
    const enriched = enrichSpdx3(makeMinimalRawSpdx(), BASE_CTX);
    const report = validateSpdx3(enriched);
    assert.equal(report.valid, true, JSON.stringify(report.failures));
    assert.equal(report.checkedElements, 17);
    assert.equal(report.passed.length, CISA_2026_ELEMENTS.length);
  });

  it("passes all 17 elements for an enriched CycloneDX 1.7 document", () => {
    const enriched = enrichCycloneDx17(makeMinimalRawCdx(), BASE_CTX);
    const report = validateCycloneDx17(enriched);
    assert.equal(report.valid, true, JSON.stringify(report.failures));
    assert.equal(report.checkedElements, 17);
    assert.equal(report.passed.length, CISA_2026_ELEMENTS.length);
  });

  it("fails SPDX 3.0 validation when required metadata or component fields are missing", () => {
    const doc = enrichSpdx3(makeMinimalRawSpdx(), BASE_CTX);
    // Remove signature, version, generation context, and package hash
    doc["@graph"] = doc["@graph"].filter(
      (n) =>
        n.spdxId !== "SPDXRef:Annotation-AuthorSignature" &&
        n.spdxId !== "SPDXRef:Annotation-SbomVersion",
    );
    const sbom = doc["@graph"].find((n) => n.type === "software_Sbom");
    if (sbom) delete sbom.software_sbomType;
    const pkg = doc["@graph"].find((n) => n.spdxId === "SPDXRef:Package-dep-1");
    if (pkg) delete pkg.verifiedUsing;

    const report = validateSpdx3(doc);
    assert.equal(report.valid, false);
    const failed = new Set(report.failures.map((f) => f.element));
    assert.ok(failed.has("sbom_author_signature"));
    assert.ok(failed.has("sbom_version"));
    assert.ok(failed.has("sbom_generation_context"));
    assert.ok(failed.has("component_hash_value"));
    assert.ok(failed.has("component_hash_algorithm"));
  });

  it("fails CycloneDX 1.7 validation when required metadata or component fields are missing", () => {
    const doc = enrichCycloneDx17(makeMinimalRawCdx(), BASE_CTX);
    delete doc.metadata.authors;
    delete doc.metadata.lifecycles;
    doc.specVersion = "1.6";
    doc.components![0]!.hashes = [];
    doc.dependencies = [];

    const report = validateCycloneDx17(doc);
    assert.equal(report.valid, false);
    const failed = new Set(report.failures.map((f) => f.element));
    assert.ok(failed.has("sbom_author"));
    assert.ok(failed.has("sbom_generation_context"));
    assert.ok(failed.has("sbom_data_format_version"));
    assert.ok(failed.has("component_hash_value"));
    assert.ok(failed.has("component_hash_algorithm"));
    assert.ok(failed.has("component_dependency_relationship"));
  });

  it("rejects non-RFC9557 timestamps in both formats", () => {
    const spdx = enrichSpdx3(makeMinimalRawSpdx(), {
      ...BASE_CTX,
      timestamp: "2026-11-23",
    });
    const cdx = enrichCycloneDx17(makeMinimalRawCdx(), {
      ...BASE_CTX,
      timestamp: "not-a-timestamp",
    });
    assert.equal(validateSpdx3(spdx).valid, false);
    assert.equal(validateCycloneDx17(cdx).valid, false);
  });
});
