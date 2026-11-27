import { createHash } from "node:crypto";
import { mkdir, readdir, readFile, stat, writeFile } from "node:fs/promises";
import path from "node:path";
import { buildChecksumsFile, type ChecksumEntry } from "./checksums.js";
import {
  enrichCycloneDx17,
  enrichSpdx3,
  type CycloneDx17Document,
  type Spdx3Document,
} from "./enrich.js";
import { buildLifecycleDocument, validateSupportUntil } from "./lifecycle.js";
import { generateNoticeFromCycloneDx } from "./notice.js";
import {
  computeFileSha256,
  ensureSyft,
  runSinglePassSyftScan,
} from "./syft.js";
import type {
  GeneratedArtifactOutputs,
  PipelineOptions,
  PipelineResult,
} from "./types.js";
import {
  formatValidationReport,
  missingStructuredSupportUntil,
  validateCycloneDx17,
  validateSpdx3,
} from "./validate.js";
import {
  buildOpenVexDocument,
  loadCuratedVexStatements,
  type OpenVexDocument,
} from "./vex.js";

async function computeDirectoryDigest(dirPath: string): Promise<string> {
  const hash = createHash("sha256");

  async function walk(currentDir: string): Promise<void> {
    const entries = await readdir(currentDir, { withFileTypes: true });
    entries.sort((a, b) => a.name.localeCompare(b.name));
    for (const entry of entries) {
      const fullPath = path.join(currentDir, entry.name);
      const relPath = path.relative(dirPath, fullPath);
      if (entry.isDirectory()) {
        hash.update(`dir:${relPath}\n`);
        await walk(fullPath);
      } else if (entry.isFile()) {
        const content = await readFile(fullPath);
        hash.update(`file:${relPath}:${content.length}\n`);
        hash.update(content);
      }
    }
  }

  await walk(dirPath);
  return hash.digest("hex");
}

interface ScanTarget {
  name: string;
  targetPath: string;
  isDirectory: boolean;
}

async function resolveScanTargets(
  artifactsPath: string,
  fallbackName: string,
): Promise<ScanTarget[]> {
  const info = await stat(artifactsPath);
  if (!info.isDirectory()) {
    return [
      {
        name: path.basename(artifactsPath),
        targetPath: artifactsPath,
        isDirectory: false,
      },
    ];
  }

  const entries = await readdir(artifactsPath, { withFileTypes: true });
  const files = entries
    .filter((e) => e.isFile() && !e.name.startsWith("."))
    .sort((a, b) => a.name.localeCompare(b.name));

  // If the directory contains release archives/binaries without ecosystem manifests,
  // scan each release artifact individually. If it is a source/project directory
  // (e.g. contains manifests like Cargo.lock, Gemfile.lock, package.json, conan.lock),
  // scan the directory as a single artifact unit.
  const manifestNames = new Set([
    "Cargo.lock",
    "Cargo.toml",
    "Gemfile.lock",
    "Gemfile",
    "package.json",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "conan.lock",
    "conanfile.txt",
    "conanfile.py",
    "CMakeLists.txt",
  ]);
  const isProjectDir = files.some((f) => manifestNames.has(f.name));

  if (isProjectDir || files.length === 0) {
    return [
      {
        name: path.basename(artifactsPath) || fallbackName,
        targetPath: artifactsPath,
        isDirectory: true,
      },
    ];
  }

  return files.map((f) => ({
    name: f.name,
    targetPath: path.join(artifactsPath, f.name),
    isDirectory: false,
  }));
}

export async function runProvenancePipeline(
  options: PipelineOptions,
): Promise<PipelineResult> {
  const supportUntil = options.supportUntil
    ? validateSupportUntil(options.supportUntil)
    : undefined;
  const vexEnabled = options.vex !== false;
  const repoRoot = options.repoRoot ?? process.cwd();
  const isPrivateRepo = options.isPrivateRepo ?? false;
  const supplier = options.supplier ?? options.author;
  const timestamp = new Date().toISOString();

  const { binPath: syftBin, version: syftVersion } = await ensureSyft({
    repoRoot,
    ...(options.syftBin ? { syftBin: options.syftBin } : {}),
  });

  await mkdir(options.outputDir, { recursive: true });

  const lifecycle = buildLifecycleDocument({
    repository: options.repository,
    releaseTag: options.releaseTag,
    supportUntil,
    author: options.author,
    attest: options.attest,
    isPrivateRepo,
    publishedAt: timestamp,
  });

  const signatureReference =
    lifecycle.attestation.status === "attested"
      ? `sigstore:slsa-build-l3:${options.repository}@${options.releaseTag}`
      : `external:${lifecycle.attestation.status}:${options.repository}@${options.releaseTag}`;

  const targets = await resolveScanTargets(
    options.artifactsPath,
    options.repository.split("/").pop() ?? "release",
  );

  const generated: GeneratedArtifactOutputs[] = [];
  const enrichedCdxDocs: CycloneDx17Document[] = [];
  const checksumEntries: ChecksumEntry[] = [];

  for (const target of targets) {
    const spdxPath = path.join(options.outputDir, `${target.name}.spdx.json`);
    const cdxPath = path.join(options.outputDir, `${target.name}.cdx.json`);

    await runSinglePassSyftScan({
      syftBin,
      targetPath: target.targetPath,
      spdxOutputPath: spdxPath,
      cdxOutputPath: cdxPath,
      sourceName: target.name,
      sourceVersion: options.releaseTag,
    });

    const artifactSha256 = target.isDirectory
      ? await computeDirectoryDigest(target.targetPath)
      : await computeFileSha256(target.targetPath);

    const rawSpdx = JSON.parse(await readFile(spdxPath, "utf8")) as Spdx3Document;
    const rawCdx = JSON.parse(
      await readFile(cdxPath, "utf8"),
    ) as CycloneDx17Document;

    const enrichCtx = {
      artifactName: target.name,
      artifactVersion: options.releaseTag,
      artifactSha256,
      author: options.author,
      supplier,
      repository: options.repository,
      supportUntil,
      generationContext: "build",
      sbomVersion: 1,
      toolName: "syft",
      toolVersion: syftVersion,
      timestamp,
      signatureReference,
    };

    const enrichedSpdx = enrichSpdx3(rawSpdx, enrichCtx);
    const enrichedCdx = enrichCycloneDx17(rawCdx, enrichCtx);

    await writeFile(spdxPath, `${JSON.stringify(enrichedSpdx, null, 2)}\n`, "utf8");
    await writeFile(cdxPath, `${JSON.stringify(enrichedCdx, null, 2)}\n`, "utf8");

    const spdxValidation = validateSpdx3(enrichedSpdx);
    const cdxValidation = validateCycloneDx17(enrichedCdx);

    if (!spdxValidation.valid || !cdxValidation.valid) {
      const details = [
        formatValidationReport(spdxValidation),
        formatValidationReport(cdxValidation),
      ].join("\n");
      throw new Error(
        `Blocking CISA 2026 Minimum Elements validation failed for "${target.name}":\n${details}`,
      );
    }

    if (supportUntil) {
      const missingSupport = missingStructuredSupportUntil(
        enrichedSpdx,
        enrichedCdx,
      );
      if (missingSupport.length > 0) {
        throw new Error(
          `Structured support-until metadata missing for "${target.name}": ${missingSupport.join(", ")}`,
        );
      }
    }

    if (!target.isDirectory) {
      checksumEntries.push({
        name: path.basename(target.targetPath),
        sha256: artifactSha256,
      });
    }
    checksumEntries.push(
      {
        name: path.basename(spdxPath),
        sha256: await computeFileSha256(spdxPath),
      },
      {
        name: path.basename(cdxPath),
        sha256: await computeFileSha256(cdxPath),
      },
    );

    enrichedCdxDocs.push(enrichedCdx);
    generated.push({
      artifactName: target.name,
      artifactPath: target.targetPath,
      artifactSha256,
      spdxPath,
      cdxPath,
      spdxValidation,
      cdxValidation,
    });
  }

  const noticeText = generateNoticeFromCycloneDx(enrichedCdxDocs, {
    repository: options.repository,
    releaseTag: options.releaseTag,
    author: options.author,
    generatedAt: timestamp,
  });
  const noticePath = path.join(options.outputDir, "NOTICE");
  await writeFile(noticePath, noticeText, "utf8");

  const lifecyclePath = path.join(options.outputDir, "lifecycle.json");
  await writeFile(
    lifecyclePath,
    `${JSON.stringify(lifecycle, null, 2)}\n`,
    "utf8",
  );

  checksumEntries.push(
    { name: "NOTICE", sha256: await computeFileSha256(noticePath) },
    { name: "lifecycle.json", sha256: await computeFileSha256(lifecyclePath) },
  );

  let openvex: OpenVexDocument | undefined;
  let openvexPath: string | undefined;
  if (vexEnabled) {
    const artifactPurls = enrichedCdxDocs
      .map((doc) => doc.metadata.component?.purl)
      .filter((purl): purl is string => Boolean(purl));
    const curatedStatements = await loadCuratedVexStatements(repoRoot);
    openvex = buildOpenVexDocument({
      author: options.author,
      timestamp,
      repository: options.repository,
      releaseTag: options.releaseTag,
      artifactPurls,
      statements: curatedStatements,
    });
    openvexPath = path.join(options.outputDir, "openvex.json");
    await writeFile(
      openvexPath,
      `${JSON.stringify(openvex, null, 2)}\n`,
      "utf8",
    );
    checksumEntries.push({
      name: "openvex.json",
      sha256: await computeFileSha256(openvexPath),
    });
  }

  const checksumsPath = path.join(options.outputDir, "SHA256SUMS.txt");
  await writeFile(checksumsPath, buildChecksumsFile(checksumEntries), "utf8");

  return {
    artifacts: generated,
    noticePath,
    lifecyclePath,
    lifecycle,
    openvexPath,
    openvex,
    checksumsPath,
    syftVersion,
  };
}
