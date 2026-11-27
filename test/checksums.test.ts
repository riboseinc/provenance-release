import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { buildChecksumsFile } from "../src/checksums.js";

describe("release checksums file", () => {
  it("emits GNU sha256sum text-mode lines sorted by name", () => {
    const text = buildChecksumsFile([
      { name: "b.bin", sha256: "b".repeat(64) },
      { name: "a.bin", sha256: "a".repeat(64) },
    ]);
    assert.equal(
      text,
      `${"a".repeat(64)}  a.bin\n${"b".repeat(64)}  b.bin\n`,
    );
  });

  it("rejects invalid digests, empty names, and duplicate names", () => {
    assert.throws(() => buildChecksumsFile([{ name: "x", sha256: "zz" }]));
    assert.throws(() =>
      buildChecksumsFile([{ name: "", sha256: "a".repeat(64) }]),
    );
    assert.throws(() =>
      buildChecksumsFile([
        { name: "x", sha256: "a".repeat(64) },
        { name: "x", sha256: "b".repeat(64) },
      ]),
    );
  });

  it("returns an empty string when there are no shipped files", () => {
    assert.equal(buildChecksumsFile([]), "");
  });
});
