#!/usr/bin/env node
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import type { CycloneDx17Document, Spdx3Document } from "./enrich.js";
import {
  resolveAttestationStatus,
  stampReleaseNotes,
} from "./lifecycle.js";
import { runPinChecks } from "./pins.js";
import { runProvenancePipeline } from "./pipeline.js";
import {
  formatValidationReport,
  validateCycloneDx17,
  validateSpdx3,
} from "./validate.js";

function parseArgs(argv: string[]): {
  command: string;
  flags: Record<string, string | boolean>;
} {
  const command = argv[0] ?? "help";
  const flags: Record<string, string | boolean> = {};

  for (let i = 1; i < argv.length; i++) {
    const token = argv[i]!;
    if (!token.startsWith("--")) continue;
    const eqIdx = token.indexOf("=");
    if (eqIdx !== -1) {
      flags[token.slice(2, eqIdx)] = token.slice(eqIdx + 1);
    } else {
      const key = token.slice(2);
      const next = argv[i + 1];
      if (next && !next.startsWith("--")) {
        flags[key] = next;
        i++;
      } else {
        flags[key] = true;
      }
    }
  }

  return { command, flags };
}

function requireString(
  flags: Record<string, string | boolean>,
  key: string,
): string {
  const val = flags[key];
  if (typeof val !== "string" || val.trim().length === 0) {
    throw new Error(`Missing required option --${key}`);
  }
  return val;
}

function getBool(
  flags: Record<string, string | boolean>,
  key: string,
  defaultValue: boolean,
): boolean {
  const val = flags[key];
  if (val === undefined) return defaultValue;
  if (typeof val === "boolean") return val;
  return val.toLowerCase() === "true" || val === "1";
}

async function cmdGenerate(
  flags: Record<string, string | boolean>,
): Promise<void> {
  const artifactsPath = requireString(flags, "artifacts");
  const outputDir = requireString(flags, "output-dir");
  const releaseTag = requireString(flags, "release-tag");
  const supportUntil = requireString(flags, "support-until");
  const author = requireString(flags, "author");
  const repository = requireString(flags, "repository");
  const supplier =
    typeof flags["supplier"] === "string" ? flags["supplier"] : undefined;
  const attest = getBool(flags, "attest", true);
  const isPrivateRepo = getBool(flags, "private-repo", false);
  const syftBin =
    typeof flags["syft-bin"] === "string" ? flags["syft-bin"] : undefined;
  const repoRoot =
    typeof flags["repo-root"] === "string" ? flags["repo-root"] : process.cwd();

  const result = await runProvenancePipeline({
    artifactsPath,
    outputDir,
    releaseTag,
    supportUntil,
    author,
    repository,
    attest,
    isPrivateRepo,
    repoRoot,
    ...(supplier ? { supplier } : {}),
    ...(syftBin ? { syftBin } : {}),
  });

  console.log(
    `Generated provenance for ${result.artifacts.length} artifact(s) using syft ${result.syftVersion}.`,
  );
  for (const item of result.artifacts) {
    console.log(formatValidationReport(item.spdxValidation));
    console.log(formatValidationReport(item.cdxValidation));
  }
  console.log(`Wrote NOTICE to ${result.noticePath}`);
  console.log(`Wrote lifecycle.json to ${result.lifecyclePath}`);
}

async function cmdValidate(
  flags: Record<string, string | boolean>,
): Promise<void> {
  const spdxFile =
    typeof flags["spdx"] === "string" ? flags["spdx"] : undefined;
  const cdxFile = typeof flags["cdx"] === "string" ? flags["cdx"] : undefined;

  if (!spdxFile && !cdxFile) {
    throw new Error("Provide at least one of --spdx <path> or --cdx <path>.");
  }

  let ok = true;
  if (spdxFile) {
    const doc = JSON.parse(await readFile(spdxFile, "utf8")) as Spdx3Document;
    const report = validateSpdx3(doc);
    console.log(formatValidationReport(report));
    if (!report.valid) ok = false;
  }
  if (cdxFile) {
    const doc = JSON.parse(
      await readFile(cdxFile, "utf8"),
    ) as CycloneDx17Document;
    const report = validateCycloneDx17(doc);
    console.log(formatValidationReport(report));
    if (!report.valid) ok = false;
  }

  if (!ok) {
    process.exitCode = 1;
  }
}

async function cmdStampNotes(
  flags: Record<string, string | boolean>,
): Promise<void> {
  const inputPath = requireString(flags, "input");
  const outputPath = requireString(flags, "output");
  const supportUntil = requireString(flags, "support-until");
  const releaseTag = requireString(flags, "release-tag");
  const repository = requireString(flags, "repository");
  const attest = getBool(flags, "attest", true);
  const isPrivateRepo = getBool(flags, "private-repo", false);

  const existing = await readFile(inputPath, "utf8");
  const stamped = stampReleaseNotes(existing, {
    supportUntil,
    releaseTag,
    repository,
    attestationStatus: resolveAttestationStatus(attest, isPrivateRepo),
  });
  await writeFile(outputPath, stamped, "utf8");
  console.log(`Stamped release notes to ${outputPath}`);
}

async function cmdCheckPins(
  flags: Record<string, string | boolean>,
): Promise<void> {
  const repoRoot =
    typeof flags["repo-root"] === "string" ? flags["repo-root"] : process.cwd();
  const result = await runPinChecks(repoRoot);
  if (!result.valid) {
    console.error("Pinning and doctrine verification failed:");
    for (const v of result.violations) {
      const loc = v.line ? `${v.file}:${v.line}` : v.file;
      console.error(`  - [${v.rule}] ${loc}: ${v.message}`);
    }
    process.exitCode = 1;
    return;
  }
  console.log(
    `Pinning check passed (${result.checkedWorkflows} workflow(s), ${result.checkedBinaries} pinned binary checksum(s), zero hardcoded instance domains).`,
  );
}

async function cmdDryRun(
  flags: Record<string, string | boolean>,
): Promise<void> {
  const repoRoot =
    typeof flags["repo-root"] === "string" ? flags["repo-root"] : process.cwd();
  const syftBin =
    typeof flags["syft-bin"] === "string" ? flags["syft-bin"] : undefined;
  const fixtureDir = path.join(repoRoot, "test", "fixtures", "rust");
  const tmpOut = await mkdtemp(path.join(os.tmpdir(), "provenance-dry-run-"));

  try {
    const result = await runProvenancePipeline({
      artifactsPath: fixtureDir,
      outputDir: tmpOut,
      releaseTag: "v0.1.0-dry-run",
      supportUntil: "2031-11-18",
      author: "Example Organization",
      repository: "example-org/example-repo",
      attest: true,
      isPrivateRepo: false,
      repoRoot,
      ...(syftBin ? { syftBin } : {}),
    });

    const notes = stampReleaseNotes("Initial release notes.", {
      supportUntil: result.lifecycle.supportUntil,
      releaseTag: result.lifecycle.releaseTag,
      repository: result.lifecycle.repository,
      attestationStatus: result.lifecycle.attestation.status,
    });
    const notesSecondPass = stampReleaseNotes(notes, {
      supportUntil: result.lifecycle.supportUntil,
      releaseTag: result.lifecycle.releaseTag,
      repository: result.lifecycle.repository,
      attestationStatus: result.lifecycle.attestation.status,
    });
    if (notes !== notesSecondPass) {
      throw new Error("Dry-run failed: release notes stamping is not idempotent.");
    }

    console.log(
      `Dry-run passed: ${result.artifacts.length} artifact(s) scanned with syft ${result.syftVersion}, both SPDX 3.0 and CycloneDX 1.7 passed all 17 CISA 2026 elements, NOTICE and lifecycle.json generated, and release-notes stamping is idempotent.`,
    );
  } finally {
    await rm(tmpOut, { recursive: true, force: true });
  }
}

async function main(): Promise<void> {
  const { command, flags } = parseArgs(process.argv.slice(2));
  switch (command) {
    case "generate":
      await cmdGenerate(flags);
      break;
    case "validate":
      await cmdValidate(flags);
      break;
    case "stamp-notes":
      await cmdStampNotes(flags);
      break;
    case "check-pins":
      await cmdCheckPins(flags);
      break;
    case "dry-run":
      await cmdDryRun(flags);
      break;
    default:
      console.log(
        "Usage: cli <generate|validate|stamp-notes|check-pins|dry-run> [--options]",
      );
      if (command !== "help") {
        process.exitCode = 1;
      }
  }
}

main().catch((err: unknown) => {
  console.error(err instanceof Error ? err.message : String(err));
  process.exitCode = 1;
});
