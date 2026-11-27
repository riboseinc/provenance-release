import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { buildOpenVexDocument, OPENVEX_CONTEXT } from "../src/vex.js";

describe("OpenVEX document generation", () => {
  const base = {
    author: "Example Security Team",
    timestamp: "2026-11-27T00:00:00.000Z",
    repository: "example-org/example-project",
    releaseTag: "v1.0.0",
    artifactPurls: ["pkg:generic/app@1.0.0"],
    statements: [],
  };

  it("emits a valid, empty OpenVEX document", () => {
    const doc = buildOpenVexDocument(base);
    assert.equal(doc["@context"], OPENVEX_CONTEXT);
    assert.ok(doc["@id"].startsWith("urn:uuid:"));
    assert.equal(doc.author, base.author);
    assert.equal(doc.timestamp, base.timestamp);
    assert.equal(doc.version, 1);
    assert.deepEqual(doc.statements, []);
  });

  it("derives a stable document id from repository and release tag", () => {
    const first = buildOpenVexDocument(base);
    const rerun = buildOpenVexDocument({
      ...base,
      timestamp: "2026-11-28T00:00:00.000Z",
    });
    assert.equal(first["@id"], rerun["@id"]);
    const other = buildOpenVexDocument({ ...base, releaseTag: "v2.0.0" });
    assert.notEqual(first["@id"], other["@id"]);
  });

  it("maps curated not-affected statements, defaulting products to the shipped artifacts", () => {
    const doc = buildOpenVexDocument({
      ...base,
      statements: [
        {
          vulnerability: "CVE-2023-12345",
          aliases: ["GHSA-xxxx"],
          justification: "vulnerable_code_not_in_execute_path",
          impactStatement: "The vulnerable path is never exercised.",
        },
      ],
    });
    assert.equal(doc.statements.length, 1);
    const stmt = doc.statements[0]!;
    assert.equal(stmt.status, "not_affected");
    assert.equal(stmt.justification, "vulnerable_code_not_in_execute_path");
    assert.equal(stmt.vulnerability.name, "CVE-2023-12345");
    assert.deepEqual(stmt.vulnerability.aliases, ["GHSA-xxxx"]);
    assert.deepEqual(stmt.products, [{ "@id": "pkg:generic/app@1.0.0" }]);
    assert.equal(stmt.impact_statement, "The vulnerable path is never exercised.");
  });

  it("honours explicit product scoping on a curated statement", () => {
    const doc = buildOpenVexDocument({
      ...base,
      statements: [
        {
          vulnerability: "CVE-2023-99999",
          justification: "component_not_present",
          products: ["pkg:generic/other@2.0.0"],
        },
      ],
    });
    assert.deepEqual(doc.statements[0]!.products, [
      { "@id": "pkg:generic/other@2.0.0" },
    ]);
    assert.equal(doc.statements[0]!.status, "not_affected");
  });
});
