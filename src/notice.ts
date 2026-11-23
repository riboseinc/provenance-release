import type { CycloneDx17Document, CycloneDxComponent } from "./enrich.js";

export interface NoticeComponent {
  name: string;
  version: string;
  identifier: string;
  producer: string;
  licenses: string[];
  copyright?: string;
  sourceUrl?: string;
}

function extractLicenses(comp: CycloneDxComponent): string[] {
  const found = new Set<string>();
  for (const entry of comp.licenses ?? []) {
    if (entry.expression) found.add(entry.expression);
    else if (entry.license?.id) found.add(entry.license.id);
    else if (entry.license?.name) found.add(entry.license.name);
  }
  if (found.size === 0) {
    found.add("NOASSERTION");
  }
  return Array.from(found).sort();
}

function extractSourceUrl(comp: CycloneDxComponent): string | undefined {
  for (const ref of comp.externalReferences ?? []) {
    if (ref.url && ref.url.trim().length > 0) {
      return ref.url.trim();
    }
  }
  return undefined;
}

/**
 * Generates a deterministic NOTICE / ATTRIBUTION document from one or more
 * CycloneDX 1.7 SBOMs emitted from the release dependency graph.
 */
export function generateNoticeFromCycloneDx(
  sboms: CycloneDx17Document[],
  options: {
    repository: string;
    releaseTag: string;
    author: string;
    generatedAt: string;
  },
): string {
  const deduped = new Map<string, NoticeComponent>();

  for (const sbom of sboms) {
    for (const comp of sbom.components ?? []) {
      if (comp.type === "file") {
        continue;
      }
      const name = comp.name.trim();
      const version = (comp.version ?? "NOASSERTION").trim();
      const identifier = (comp.purl ?? comp.cpe ?? `${name}@${version}`).trim();
      const producer = (
        comp.supplier?.name ??
        comp.manufacturer?.name ??
        comp.author ??
        "NOASSERTION"
      ).trim();
      const key = `${name.toLowerCase()}@@${version}@@${identifier}`;
      if (!deduped.has(key)) {
        const sourceUrl = extractSourceUrl(comp);
        const item: NoticeComponent = {
          name,
          version,
          identifier,
          producer,
          licenses: extractLicenses(comp),
        };
        if (comp.copyright && comp.copyright.trim().length > 0) {
          item.copyright = comp.copyright.trim();
        }
        if (sourceUrl) {
          item.sourceUrl = sourceUrl;
        }
        deduped.set(key, item);
      }
    }
  }

  const sorted = Array.from(deduped.values()).sort((a, b) => {
    const nameCmp = a.name.localeCompare(b.name);
    if (nameCmp !== 0) return nameCmp;
    const verCmp = a.version.localeCompare(b.version);
    if (verCmp !== 0) return verCmp;
    return a.identifier.localeCompare(b.identifier);
  });

  const licenseSummary = new Set<string>();
  for (const item of sorted) {
    for (const lic of item.licenses) {
      licenseSummary.add(lic);
    }
  }

  const lines: string[] = [
    `THIRD-PARTY SOFTWARE NOTICES AND ATTRIBUTION`,
    `============================================`,
    "",
    `Repository: ${options.repository}`,
    `Release: ${options.releaseTag}`,
    `SBOM Author: ${options.author}`,
    `Generated: ${options.generatedAt}`,
    "",
    "This file lists the third-party software components, license identifiers, and",
    "copyright attributions derived automatically from the release dependency graph.",
    "",
    `Total third-party components: ${sorted.length}`,
    `Distinct license expressions: ${licenseSummary.size > 0 ? Array.from(licenseSummary).sort().join(", ") : "None"}`,
    "",
  ];

  if (sorted.length === 0) {
    lines.push("No third-party software components were identified in this release.");
    lines.push("");
  } else {
    for (const comp of sorted) {
      lines.push("--------------------------------------------------------------------------------");
      lines.push(`Component: ${comp.name}`);
      lines.push(`Version: ${comp.version}`);
      lines.push(`Identifier: ${comp.identifier}`);
      lines.push(`Producer: ${comp.producer}`);
      lines.push(`License: ${comp.licenses.join(", ")}`);
      if (comp.copyright) {
        lines.push(`Copyright: ${comp.copyright}`);
      }
      if (comp.sourceUrl) {
        lines.push(`Source: ${comp.sourceUrl}`);
      }
      lines.push("");
    }
  }

  return `${lines.join("\n").trimEnd()}\n`;
}
