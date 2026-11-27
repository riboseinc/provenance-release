import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { buildOpenVexDocument, OPENVEX_CONTEXT } from "../src/vex.js";

describe("OpenVEX document generation", () => {
  const base = {
    author: "Example Security Team",
    timestamp: "2026-11-27T00:00:00.000Z",
    repository: "example-org/example-project",
    releaseTag: "v1.0.0",
    productName: "app",
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

  it("scopes curated statements to the named product", () => {
    const statements = [
      {
        vulnerability: "CVE-2023-99999",
        justification: "component_not_present" as const,
        appliesTo: ["fontist"],
      },
    ];

    // Not this product (base productName is "app"): the claim is omitted.
    const forApp = buildOpenVexDocument({ ...base, statements });
    assert.equal(forApp.statements.length, 0);

    // For fontist: the claim is included, scoped to the release's artifacts.
    const forFontist = buildOpenVexDocument({
      ...base,
      productName: "fontist",
      statements,
    });
    assert.equal(forFontist.statements.length, 1);
    assert.equal(forFontist.statements[0]!.status, "not_affected");
    assert.equal(
      forFontist.statements[0]!.justification,
      "component_not_present",
    );
    assert.deepEqual(forFontist.statements[0]!.products, [
      { "@id": "pkg:generic/app@1.0.0" },
    ]);
  });

  it("supports affected and under_investigation statuses with release-tag scoping", () => {
    const statements = [
      {
        vulnerability: "CVE-2026-85396",
        status: "affected" as const,
        actionStatement: "Upgrade past 3.0.10.",
        appliesTo: ["fontist"],
        releaseTagPrefixes: ["3.0.10", "v3.0.10"],
      },
      {
        vulnerability: "CVE-2026-126080",
        status: "under_investigation" as const,
        appliesTo: ["fontist"],
        releaseTagPrefixes: ["3.0.10", "v3.0.10"],
      },
    ];

    const on3010 = buildOpenVexDocument({
      ...base,
      productName: "fontist",
      releaseTag: "3.0.10-2",
      statements,
    });
    assert.equal(on3010.statements.length, 2);
    assert.equal(on3010.statements[0]!.status, "affected");
    assert.equal(
      on3010.statements[0]!.action_statement,
      "Upgrade past 3.0.10.",
    );
    assert.equal(
      on3010.statements[0]!.action_statement_timestamp,
      base.timestamp,
    );
    assert.equal(on3010.statements[1]!.status, "under_investigation");

    // Fixed newer release must not inherit old-snapshot affected claims.
    const on3043 = buildOpenVexDocument({
      ...base,
      productName: "fontist",
      releaseTag: "3.0.43",
      statements,
    });
    assert.equal(on3043.statements.length, 0);
  });

  it("enforces OpenVEX required fields per status", () => {
    assert.throws(() =>
      buildOpenVexDocument({
        ...base,
        statements: [{ vulnerability: "CVE-2026-00001", status: "not_affected" }],
      }),
    );
    assert.throws(() =>
      buildOpenVexDocument({
        ...base,
        statements: [{ vulnerability: "CVE-2026-00002", status: "affected" }],
      }),
    );
  });
});
