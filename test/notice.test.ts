import assert from "node:assert/strict";
import { describe, it } from "node:test";
import type { CycloneDx17Document } from "../src/enrich.js";
import { generateNoticeFromCycloneDx } from "../src/notice.js";

describe("NOTICE / ATTRIBUTION generator", () => {
  it("deduplicates, sorts deterministically, and renders license and copyright metadata", () => {
    const sbom: CycloneDx17Document = {
      bomFormat: "CycloneDX",
      specVersion: "1.7",
      version: 1,
      metadata: {
        timestamp: "2026-11-23T05:00:00Z",
      },
      components: [
        {
          type: "library",
          name: "zlib",
          version: "1.3.1",
          purl: "pkg:conan/zlib@1.3.1",
          supplier: { name: "Jean-loup Gailly and Mark Adler" },
          licenses: [{ license: { id: "Zlib" } }],
          copyright: "Copyright (C) 1995-2024 Jean-loup Gailly and Mark Adler",
        },
        {
          type: "library",
          name: "botan",
          version: "3.5.0",
          purl: "pkg:conan/botan@3.5.0",
          supplier: { name: "Jack Lloyd" },
          licenses: [{ expression: "BSD-2-Clause" }],
          externalReferences: [
            { type: "website", url: "https://botan.randombit.net" },
          ],
        },
        // Duplicate entry to verify deduplication
        {
          type: "library",
          name: "botan",
          version: "3.5.0",
          purl: "pkg:conan/botan@3.5.0",
          supplier: { name: "Jack Lloyd" },
          licenses: [{ expression: "BSD-2-Clause" }],
        },
        // File entry should not be treated as a third-party package
        {
          type: "file",
          name: "/conan.lock",
        },
      ],
    };

    const notice = generateNoticeFromCycloneDx([sbom], {
      repository: "example-org/crypto-lib",
      releaseTag: "v1.0.0",
      author: "Example Org",
      generatedAt: "2026-11-23T05:00:00Z",
    });

    assert.ok(notice.includes("Total third-party components: 2"));
    assert.ok(notice.includes("BSD-2-Clause, Zlib"));
    assert.ok(notice.includes("Copyright (C) 1995-2024"));
    assert.ok(notice.includes("https://botan.randombit.net"));
    assert.ok(notice.indexOf("Component: botan") < notice.indexOf("Component: zlib"));
  });
});
