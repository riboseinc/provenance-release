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
  action_statement?: string;
  action_statement_timestamp?: string;
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
 * A curated VEX statement stored in `tools/vex-statements.json` and merged into
 * matching releases' OpenVEX documents. Defaults to `status: "not_affected"`.
 */
export interface CuratedVexStatement {
  vulnerability: string;
  aliases?: string[];
  status?: VexStatus;
  justification?: VexJustification;
  impactStatement?: string;
  actionStatement?: string;
  statusNotes?: string;
  /**
   * Product names this claim applies to (e.g. ["fontist"]). Omit to apply the
   * claim to every product. Scopes a claim to the right release so, for
   * example, a fontist-only "rake is absent" claim never lands in metanorma's
   * VEX (where rake is present). Plain product names, not PURLs.
   */
  appliesTo?: string[];
  /**
   * Optional release-tag prefixes (e.g. ["3.0.10", "v3.0.10"]) scoping
   * version-specific statements (`affected`, `under_investigation`) so they
   * never taint newer, fixed releases.
   */
  releaseTagPrefixes?: string[];
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

  // Only carry claims scoped to this product and (if specified) release tag,
  // so a claim about one package or old snapshot never leaks into another.
  const applicable = options.statements.filter((s) => {
    const productMatch =
      !s.appliesTo ||
      s.appliesTo.length === 0 ||
      s.appliesTo.includes(options.productName);
    if (!productMatch) return false;
    if (!s.releaseTagPrefixes || s.releaseTagPrefixes.length === 0) return true;
    return s.releaseTagPrefixes.some((prefix) =>
      options.releaseTag.startsWith(prefix),
    );
  });

  const statements: OpenVexStatement[] = applicable.map((curated) => {
    const status: VexStatus = curated.status ?? "not_affected";
    if (
      status === "not_affected" &&
      !curated.justification &&
      !curated.impactStatement
    ) {
      throw new Error(
        `OpenVEX not_affected statement for ${curated.vulnerability} must specify a justification or impactStatement.`,
      );
    }
    if (status === "affected" && !curated.actionStatement) {
      throw new Error(
        `OpenVEX affected statement for ${curated.vulnerability} must specify an actionStatement.`,
      );
    }

    const statement: OpenVexStatement = {
      vulnerability: { name: curated.vulnerability },
      products: defaultProducts,
      status,
    };
    if (curated.justification) {
      statement.justification = curated.justification;
    }
    if (curated.aliases && curated.aliases.length > 0) {
      statement.vulnerability.aliases = curated.aliases;
    }
    if (curated.impactStatement) {
      statement.impact_statement = curated.impactStatement;
    }
    if (curated.actionStatement) {
      statement.action_statement = curated.actionStatement;
      statement.action_statement_timestamp = options.timestamp;
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
