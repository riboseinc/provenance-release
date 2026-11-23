import assert from "node:assert/strict";
import path from "node:path";
import { describe, it } from "node:test";
import {
  checkSyftManifest,
  checkWorkflowContent,
  runPinChecks,
} from "../src/pins.js";
import type { SyftManifest } from "../src/types.js";

describe("Pinning and doctrine verification", () => {
  it("accepts 40-char SHA-pinned GitHub Actions and rejects floating tags", () => {
    const validYaml = `
jobs:
  test:
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
`;
    assert.equal(checkWorkflowContent("ci.yml", validYaml).length, 0);

    const invalidYaml = `
jobs:
  test:
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@main
`;
    const violations = checkWorkflowContent("ci.yml", invalidYaml);
    assert.equal(violations.length, 2);
    assert.ok(violations.every((v) => v.rule === "action-sha-pin"));
  });

  it("rejects hardcoded instance domains", () => {
    const badDomain = ["ribose", "com"].join(".");
    const yaml = `
jobs:
  test:
    env:
      URL: https://provenance.${badDomain}
`;
    const violations = checkWorkflowContent("release.yml", yaml);
    assert.equal(violations.length, 1);
    assert.equal(violations[0]!.rule, "no-hardcoded-instance");
  });

  it("validates syft binary checksum manifest", () => {
    const badManifest: SyftManifest = {
      tool: "syft",
      version: "1.57.2",
      releaseUrl: "https://github.com/anchore/syft/releases/tag/v1.57.2",
      checksumsUrl:
        "https://github.com/anchore/syft/releases/download/v1.57.2/syft_1.57.2_checksums.txt",
      platforms: {
        "linux-x64": {
          filename: "syft_1.57.2_linux_amd64.tar.gz",
          url: "http://insecure.example/syft.tar.gz",
          sha256: "not-a-sha256",
        },
      },
    };
    const res = checkSyftManifest("tools/syft.json", badManifest);
    assert.ok(res.violations.length >= 2);
  });

  it("passes all pinning and zero-hardcoding checks on the repository itself", async () => {
    const repoRoot = path.resolve(import.meta.dirname, "..", "..");
    const result = await runPinChecks(repoRoot);
    assert.equal(result.valid, true, JSON.stringify(result.violations, null, 2));
    assert.ok(result.checkedWorkflows >= 2);
    assert.ok(result.checkedBinaries >= 4);
  });
});
