import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  buildLifecycleDocument,
  resolveAttestationStatus,
  stampReleaseNotes,
  SUPPORT_PERIOD_END_MARKER,
  SUPPORT_PERIOD_START_MARKER,
  validateSupportUntil,
} from "../src/lifecycle.js";

describe("support-until and lifecycle stamper", () => {
  it("accepts valid YYYY-MM-DD dates including leap years", () => {
    assert.equal(validateSupportUntil("2031-11-18"), "2031-11-18");
    assert.equal(validateSupportUntil("2028-02-29"), "2028-02-29");
  });

  it("rejects malformed or impossible calendar dates", () => {
    assert.throws(() => validateSupportUntil("2031/11/18"));
    assert.throws(() => validateSupportUntil("2031-13-01"));
    assert.throws(() => validateSupportUntil("2031-02-29"));
    assert.throws(() => validateSupportUntil("2031-04-31"));
    assert.throws(() => validateSupportUntil(""));
  });

  it("handles public, private-exception, and disabled attestation modes", () => {
    assert.equal(resolveAttestationStatus(true, false), "attested");
    assert.equal(resolveAttestationStatus(true, true), "skipped-private-repo");
    assert.equal(resolveAttestationStatus(false, false), "disabled");
    assert.equal(resolveAttestationStatus(false, true), "disabled");

    const lifecycle = buildLifecycleDocument({
      repository: "example-org/private-repo",
      releaseTag: "v2.0.0",
      supportUntil: "2030-06-30",
      author: "Example Org",
      attest: true,
      isPrivateRepo: true,
      publishedAt: "2026-11-23T05:00:00Z",
    });
    assert.equal(lifecycle.attestation.enabled, false);
    assert.equal(lifecycle.attestation.status, "skipped-private-repo");
    assert.equal(lifecycle.supportUntil, "2030-06-30");
  });

  it("stamps GitHub Release notes idempotently and updates existing sections in place", () => {
    const initial = "# Release v1.0.0\n\nBug fixes and performance improvements.";
    const first = stampReleaseNotes(initial, {
      supportUntil: "2031-11-18",
      releaseTag: "v1.0.0",
      repository: "example-org/app",
      attestationStatus: "attested",
    });

    assert.ok(first.includes(SUPPORT_PERIOD_START_MARKER));
    assert.ok(first.includes(SUPPORT_PERIOD_END_MARKER));
    assert.ok(first.includes("2031-11-18"));
    assert.ok(first.includes("gh attestation verify <artifact> -R example-org/app"));

    const second = stampReleaseNotes(first, {
      supportUntil: "2031-11-18",
      releaseTag: "v1.0.0",
      repository: "example-org/app",
      attestationStatus: "attested",
    });
    assert.equal(second, first);

    const updated = stampReleaseNotes(second, {
      supportUntil: "2032-12-31",
      releaseTag: "v1.0.0",
      repository: "example-org/app",
      attestationStatus: "skipped-private-repo",
    });
    assert.ok(updated.includes("2032-12-31"));
    assert.ok(!updated.includes("2031-11-18"));
    assert.equal(
      updated.split(SUPPORT_PERIOD_START_MARKER).length - 1,
      1,
    );
  });
});
