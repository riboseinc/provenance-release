import { createHash } from "node:crypto";
import { execFile } from "node:child_process";
import { createWriteStream } from "node:fs";
import { access, chmod, mkdir, readFile, stat } from "node:fs/promises";
import path from "node:path";
import { pipeline } from "node:stream/promises";
import { promisify } from "node:util";
import type { SyftManifest, SyftPlatformSpec } from "./types.js";

const execFileAsync = promisify(execFile);

export const MIN_SYFT_VERSION = "1.57.2";

export function parseSemver(version: string): [number, number, number] {
  const cleaned = version.trim().replace(/^v/, "").split("-")[0] ?? "";
  const parts = cleaned.split(".");
  if (parts.length !== 3) {
    throw new Error(`Invalid semantic version: "${version}"`);
  }
  const nums = parts.map((p) => Number.parseInt(p, 10));
  if (nums.some((n) => !Number.isInteger(n) || n < 0)) {
    throw new Error(`Invalid semantic version: "${version}"`);
  }
  return [nums[0]!, nums[1]!, nums[2]!];
}

export function compareSemver(a: string, b: string): number {
  const [aMaj, aMin, aPat] = parseSemver(a);
  const [bMaj, bMin, bPat] = parseSemver(b);
  if (aMaj !== bMaj) return aMaj - bMaj;
  if (aMin !== bMin) return aMin - bMin;
  return aPat - bPat;
}

export async function loadSyftManifest(repoRoot: string): Promise<SyftManifest> {
  const manifestPath = path.join(repoRoot, "tools", "syft.json");
  const raw = await readFile(manifestPath, "utf8");
  return JSON.parse(raw) as SyftManifest;
}

export function getPlatformKey(
  platform: NodeJS.Platform = process.platform,
  arch: string = process.arch,
): string {
  return `${platform}-${arch}`;
}

export async function computeFileSha256(filePath: string): Promise<string> {
  const data = await readFile(filePath);
  return createHash("sha256").update(data).digest("hex");
}

export async function verifySyftVersion(syftBin: string): Promise<string> {
  const { stdout } = await execFileAsync(syftBin, ["version", "-o", "json"]);
  const parsed = JSON.parse(stdout) as { version?: string };
  if (!parsed.version) {
    throw new Error(`Unable to determine syft version from binary: ${syftBin}`);
  }
  if (compareSemver(parsed.version, MIN_SYFT_VERSION) < 0) {
    throw new Error(
      `syft ${parsed.version} is below the required minimum version ${MIN_SYFT_VERSION}.`,
    );
  }
  return parsed.version;
}

async function downloadFile(url: string, destPath: string): Promise<void> {
  const response = await fetch(url);
  if (!response.ok || !response.body) {
    throw new Error(`Failed to download ${url}: HTTP ${response.status}`);
  }
  await mkdir(path.dirname(destPath), { recursive: true });
  await pipeline(
    response.body as unknown as NodeJS.ReadableStream,
    createWriteStream(destPath),
  );
}

export async function ensureSyft(options: {
  repoRoot: string;
  syftBin?: string;
  cacheDir?: string;
}): Promise<{ binPath: string; version: string }> {
  const explicitBin = options.syftBin ?? process.env["SYFT_BIN"];
  if (explicitBin) {
    const version = await verifySyftVersion(explicitBin);
    return { binPath: explicitBin, version };
  }

  const manifest = await loadSyftManifest(options.repoRoot);
  const platformKey = getPlatformKey();
  const spec: SyftPlatformSpec | undefined = manifest.platforms[platformKey];
  if (!spec) {
    throw new Error(
      `No pinned syft binary entry for platform "${platformKey}" in tools/syft.json.`,
    );
  }

  const cacheDir =
    options.cacheDir ??
    path.join(options.repoRoot, ".syft-cache", manifest.version, platformKey);
  const binPath = path.join(cacheDir, "syft");

  try {
    await access(binPath);
    const version = await verifySyftVersion(binPath);
    return { binPath, version };
  } catch {
    // Download and verify checksum before extraction.
  }

  await mkdir(cacheDir, { recursive: true });
  const archivePath = path.join(cacheDir, spec.filename);
  await downloadFile(spec.url, archivePath);

  const actualSha = await computeFileSha256(archivePath);
  if (actualSha !== spec.sha256) {
    throw new Error(
      `Checksum mismatch for ${spec.filename}: expected ${spec.sha256}, got ${actualSha}.`,
    );
  }

  await execFileAsync("tar", ["-xzf", archivePath, "-C", cacheDir, "syft"]);
  await chmod(binPath, 0o755);

  const version = await verifySyftVersion(binPath);
  return { binPath, version };
}

export interface SyftScanParams {
  syftBin: string;
  targetPath: string;
  spdxOutputPath: string;
  cdxOutputPath: string;
  sourceName: string;
  sourceVersion: string;
}

/**
 * Runs syft in a single scan pass, explicitly requesting SPDX 3.0
 * (-o spdx-json@3.0) and CycloneDX 1.7 (-o cyclonedx-json@1.7).
 */
export async function runSinglePassSyftScan(
  params: SyftScanParams,
): Promise<void> {
  const targetStats = await stat(params.targetPath);
  const scheme = targetStats.isDirectory() ? "dir" : "file";
  const scanTarget = `${scheme}:${params.targetPath}`;

  await mkdir(path.dirname(params.spdxOutputPath), { recursive: true });
  await mkdir(path.dirname(params.cdxOutputPath), { recursive: true });

  const args = [
    "scan",
    scanTarget,
    "-o",
    `spdx-json@3.0=${params.spdxOutputPath}`,
    "-o",
    `cyclonedx-json@1.7=${params.cdxOutputPath}`,
    "--source-name",
    params.sourceName,
    "--source-version",
    params.sourceVersion,
  ];

  await execFileAsync(params.syftBin, args, {
    maxBuffer: 64 * 1024 * 1024,
  });
}
