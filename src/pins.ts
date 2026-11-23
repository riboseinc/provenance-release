import { readdir, readFile } from "node:fs/promises";
import path from "node:path";
import type { PinCheckResult, PinViolation, SyftManifest } from "./types.js";

const USES_LINE_REGEX = /^\s*(?:-\s*)?uses:\s*["']?([^"'\s#]+)["']?/;
const FULL_SHA_PIN_REGEX = /^[^@]+@[0-9a-f]{40}$/;
const SHA256_HEX_REGEX = /^[0-9a-f]{64}$/;
const FORBIDDEN_INSTANCE_DOMAIN = ["ribose", "com"].join(".");

export function checkWorkflowContent(
  filePath: string,
  content: string,
): PinViolation[] {
  const violations: PinViolation[] = [];
  const lines = content.split(/\r?\n/);

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    const lineNum = i + 1;

    if (line.toLowerCase().includes(FORBIDDEN_INSTANCE_DOMAIN)) {
      violations.push({
        file: filePath,
        line: lineNum,
        rule: "no-hardcoded-instance",
        message: `Workflow must not contain hardcoded instance domain "${FORBIDDEN_INSTANCE_DOMAIN}".`,
      });
    }

    const usesMatch = USES_LINE_REGEX.exec(line);
    if (!usesMatch) continue;

    const target = usesMatch[1]!;
    if (target.startsWith("./") || target.startsWith("docker://")) {
      if (target.startsWith("docker://") && !/@sha256:[0-9a-f]{64}$/.test(target)) {
        violations.push({
          file: filePath,
          line: lineNum,
          rule: "action-sha-pin",
          message: `Docker action "${target}" must be pinned by @sha256:<64-hex-digest>.`,
        });
      }
      continue;
    }

    if (!FULL_SHA_PIN_REGEX.test(target)) {
      violations.push({
        file: filePath,
        line: lineNum,
        rule: "action-sha-pin",
        message: `GitHub Action "${target}" must be pinned to a full 40-character commit SHA.`,
      });
    }
  }

  return violations;
}

export function checkSyftManifest(
  filePath: string,
  manifest: SyftManifest,
): { checkedBinaries: number; violations: PinViolation[] } {
  const violations: PinViolation[] = [];
  const entries = Object.entries(manifest.platforms ?? {});

  if (entries.length === 0) {
    violations.push({
      file: filePath,
      rule: "binary-checksum-pin",
      message: "tools/syft.json must declare at least one platform binary.",
    });
    return { checkedBinaries: 0, violations };
  }

  for (const [platform, spec] of entries) {
    if (!SHA256_HEX_REGEX.test(spec.sha256)) {
      violations.push({
        file: filePath,
        rule: "binary-checksum-pin",
        message: `Platform "${platform}" has an invalid SHA-256 checksum "${spec.sha256}".`,
      });
    }
    if (!spec.url.startsWith("https://")) {
      violations.push({
        file: filePath,
        rule: "binary-checksum-pin",
        message: `Platform "${platform}" download URL must use HTTPS.`,
      });
    }
    if (!spec.url.includes(manifest.version)) {
      violations.push({
        file: filePath,
        rule: "binary-checksum-pin",
        message: `Platform "${platform}" download URL does not match pinned version ${manifest.version}.`,
      });
    }
  }

  return { checkedBinaries: entries.length, violations };
}

export async function runPinChecks(repoRoot: string): Promise<PinCheckResult> {
  const violations: PinViolation[] = [];
  let checkedWorkflows = 0;

  const workflowsDir = path.join(repoRoot, ".github", "workflows");
  try {
    const entries = await readdir(workflowsDir);
    for (const entry of entries) {
      if (!entry.endsWith(".yml") && !entry.endsWith(".yaml")) continue;
      checkedWorkflows++;
      const fullPath = path.join(workflowsDir, entry);
      const relPath = path.relative(repoRoot, fullPath);
      const content = await readFile(fullPath, "utf8");
      violations.push(...checkWorkflowContent(relPath, content));
    }
  } catch {
    violations.push({
      file: ".github/workflows",
      rule: "action-sha-pin",
      message: "Missing .github/workflows directory.",
    });
  }

  // Verify zero hardcoded instance domain in src/ files as well.
  const srcDir = path.join(repoRoot, "src");
  try {
    const srcFiles = await readdir(srcDir);
    for (const file of srcFiles) {
      if (!file.endsWith(".ts")) continue;
      const fullPath = path.join(srcDir, file);
      const relPath = path.relative(repoRoot, fullPath);
      const content = await readFile(fullPath, "utf8");
      const lines = content.split(/\r?\n/);
      for (let i = 0; i < lines.length; i++) {
        if (lines[i]!.toLowerCase().includes(FORBIDDEN_INSTANCE_DOMAIN)) {
          violations.push({
            file: relPath,
            line: i + 1,
            rule: "no-hardcoded-instance",
            message: `Source file must not contain hardcoded instance domain "${FORBIDDEN_INSTANCE_DOMAIN}".`,
          });
        }
      }
    }
  } catch {
    // No src directory to scan.
  }

  const manifestRel = path.join("tools", "syft.json");
  const manifestFull = path.join(repoRoot, manifestRel);
  let checkedBinaries = 0;
  try {
    const raw = await readFile(manifestFull, "utf8");
    const manifest = JSON.parse(raw) as SyftManifest;
    const result = checkSyftManifest(manifestRel, manifest);
    checkedBinaries = result.checkedBinaries;
    violations.push(...result.violations);
  } catch (err) {
    violations.push({
      file: manifestRel,
      rule: "binary-checksum-pin",
      message: `Unable to load or parse ${manifestRel}: ${err instanceof Error ? err.message : String(err)}`,
    });
  }

  return {
    valid: violations.length === 0,
    checkedWorkflows,
    checkedBinaries,
    violations,
  };
}
