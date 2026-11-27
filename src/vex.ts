import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import path from "node:path";

export const OPENVEX_CONTEXT = "https://openvex.dev/ns/v0.2.0";

export type VexStatus =
  | "not_affected"
  | "affected"
  | "fixed"
  | "under_investigation";

export type VexJustification =
  | "component_not_present"
  | "vulnerable_code_not_in_execute_path"
  | "vulnerable_code_cannot_be_controlled_by_adversary"
  | "inline_mitigations_already_exist";

export interface OpenVexStatement {
  vulnerability: {
    name: string;
    aliases?: string[];
  };
  products: Array<{ "@id": string }>;
  status: VexStatus;
  justification?: VexJustification;
  impact_statement?: string;
  status_notes?: string;
}

export interface OpenVexDocument {
  "@context": string;
  "@id": string;
  author: string;
  timestamp: string;
  version: number;
  statements: OpenVexStatement[];
}

/**
 * A curated "not affected" claim for a known-noisy advisory. Stored as data in
 * `tools/vex-statements.json` and merged into every release's OpenVEX document.
 * When `products` is omitted the claim applies to every shipped artifact.
 */
export interface CuratedVexStatement {
  vulnerability: string;
  aliases?: string[];
  justification: VexJustification;
  impactStatement?: string;
  statusNotes?: string;
  /**
   * Product names this claim applies to (e.g. ["fontist"]). Omit to apply the
   * claim to every product. Scopes a claim to the right release so, for
   * example, a fontist-only "rake is absent" claim never lands in metanorma's
   * VEX (where rake is present). Plain product names, not PURLs.
   */
  appliesTo?: string[];
}

/** Deterministic RFC 4122 version-5-shaped UUID derived from a seed string. */
function deterministicUuid(seed: string): string {
  const bytes = createHash("sha256").update(seed).digest().subarray(0, 16);
  bytes[6] = (bytes[6]! & 0x0f) | 0x50;
  bytes[8] = (bytes[8]! & 0x3f) | 0x80;
  const hex = bytes.toString("hex");
  return [
    hex.slice(0, 8),
    hex.slice(8, 12),
    hex.slice(12, 16),
    hex.slice(16, 20),
    hex.slice(20),
  ].join("-");
}

export async function loadCuratedVexStatements(
  repoRoot: string,
): Promise<CuratedVexStatement[]> {
  const manifestPath = path.join(repoRoot, "tools", "vex-statements.json");
  let raw: string;
  try {
    raw = await readFile(manifestPath, "utf8");
  } catch {
    return [];
  }
  const parsed: unknown = JSON.parse(raw);
  if (!Array.isArray(parsed)) {
    throw new Error(`${manifestPath} must contain a JSON array.`);
  }
  return parsed as CuratedVexStatement[];
}

export function buildOpenVexDocument(options: {
  author: string;
  timestamp: string;
  repository: string;
  releaseTag: string;
  productName: string;
  artifactPurls: string[];
  statements: CuratedVexStatement[];
}): OpenVexDocument {
  const defaultProducts = options.artifactPurls.map((purl) => ({ "@id": purl }));

  // Only carry claims scoped to this product (or unscoped ones), so a claim
  // about one package never appears in another package's VEX.
  const applicable = options.statements.filter(
    (s) =>
      !s.appliesTo ||
      s.appliesTo.length === 0 ||
      s.appliesTo.includes(options.productName),
  );

  const statements: OpenVexStatement[] = applicable.map((curated) => {
    const statement: OpenVexStatement = {
      vulnerability: { name: curated.vulnerability },
      products: defaultProducts,
      status: "not_affected",
      justification: curated.justification,
    };
    if (curated.aliases && curated.aliases.length > 0) {
      statement.vulnerability.aliases = curated.aliases;
    }
    if (curated.impactStatement) {
      statement.impact_statement = curated.impactStatement;
    }
    if (curated.statusNotes) {
      statement.status_notes = curated.statusNotes;
    }
    return statement;
  });

  return {
    "@context": OPENVEX_CONTEXT,
    "@id": `urn:uuid:${deterministicUuid(`${options.repository}@${options.releaseTag}`)}`,
    author: options.author,
    timestamp: options.timestamp,
    version: 1,
    statements,
  };
}
