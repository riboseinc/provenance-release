import {
  CISA_2026_ELEMENTS,
  type Cisa2026Element,
  type ValidationFailure,
  type ValidationReport,
} from "./types.js";
import type { CycloneDx17Document, Spdx3Document } from "./enrich.js";

// RFC 9557 / ISO 8601 timestamp with explicit timezone offset or Z.
const RFC9557_TIMESTAMP =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})(?:\[[^\]]+\])?$/;

function isNonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0;
}

function finalizeReport(
  format: "spdx-3.0" | "cyclonedx-1.7",
  failures: ValidationFailure[],
): ValidationReport {
  const failedSet = new Set(failures.map((f) => f.element));
  const passed: Cisa2026Element[] = CISA_2026_ELEMENTS.filter(
    (el) => !failedSet.has(el),
  );
  return {
    valid: failures.length === 0,
    format,
    checkedElements: CISA_2026_ELEMENTS.length,
    passed,
    failures,
  };
}

export function validateSpdx3(doc: Spdx3Document): ValidationReport {
  const failures: ValidationFailure[] = [];
  const fail = (
    element: Cisa2026Element,
    message: string,
    target?: string,
  ): void => {
    failures.push(target ? { element, message, target } : { element, message });
  };

  const graph = Array.isArray(doc?.["@graph"]) ? doc["@graph"] : [];
  const contextStr = Array.isArray(doc?.["@context"])
    ? doc["@context"].join(" ")
    : String(doc?.["@context"] ?? "");

  const byId = new Map<string, (typeof graph)[number]>();
  for (const node of graph) {
    if (isNonEmptyString(node.spdxId)) byId.set(node.spdxId, node);
    if (isNonEmptyString(node["@id"])) byId.set(node["@id"], node);
  }

  const creationInfo = graph.find((n) => n.type === "CreationInfo");
  const sbomNode = graph.find((n) => n.type === "software_Sbom");
  const annotations = graph.filter((n) => n.type === "Annotation");
  const packages = graph.filter((n) => n.type === "software_Package");
  const relationships = graph.filter((n) => n.type === "Relationship");

  // 1. SBOM Author
  const createdBy = creationInfo?.createdBy ?? [];
  const hasAuthor =
    createdBy.length > 0 &&
    createdBy.some((id) => isNonEmptyString(byId.get(id)?.name));
  if (!hasAuthor) {
    fail(
      "sbom_author",
      "Missing SBOM Author in CreationInfo.createdBy referencing a named Organization or Person.",
    );
  }

  // 2. SBOM Author Signature
  const hasSignature = annotations.some(
    (a) =>
      isNonEmptyString(a.statement) &&
      a.statement.startsWith("sbomAuthorSignature=") &&
      a.statement.length > "sbomAuthorSignature=".length,
  );
  if (!hasSignature) {
    fail(
      "sbom_author_signature",
      "Missing SBOM Author Signature annotation (sbomAuthorSignature=...).",
    );
  }

  // 3. SBOM Data Format Name
  if (!contextStr.toLowerCase().includes("spdx")) {
    fail(
      "sbom_data_format_name",
      "SPDX @context does not identify SPDX as the SBOM data format.",
    );
  }

  // 4. SBOM Data Format Version
  const specVersion = creationInfo?.specVersion;
  if (!isNonEmptyString(specVersion) || !specVersion.startsWith("3.0")) {
    fail(
      "sbom_data_format_version",
      `SPDX CreationInfo.specVersion must be 3.0.x, got "${String(specVersion ?? "")}".`,
    );
  }

  // 5. SBOM Generation Context
  const sbomTypes = sbomNode?.software_sbomType ?? [];
  if (sbomTypes.length === 0 || !sbomTypes.every(isNonEmptyString)) {
    fail(
      "sbom_generation_context",
      "Missing SBOM Generation Context in software_Sbom.software_sbomType.",
    );
  }

  // 6. SBOM Timestamp
  const created = creationInfo?.created;
  if (!isNonEmptyString(created) || !RFC9557_TIMESTAMP.test(created)) {
    fail(
      "sbom_timestamp",
      `SBOM timestamp must be an RFC 9557 / ISO 8601 timestamp, got "${String(created ?? "")}".`,
    );
  }

  // 7 & 8. SBOM Tool Name & SBOM Tool Version
  const createdUsing = creationInfo?.createdUsing ?? [];
  const toolNodes = createdUsing
    .map((id) => byId.get(id))
    .filter((n): n is NonNullable<typeof n> => Boolean(n && n.type === "Tool"));
  const primaryToolName = toolNodes.find((t) => isNonEmptyString(t.name))?.name;
  if (!isNonEmptyString(primaryToolName)) {
    fail("sbom_tool_name", "Missing SBOM Tool Name in CreationInfo.createdUsing.");
    fail(
      "sbom_tool_version",
      "Missing SBOM Tool Version because no Tool element is present.",
    );
  } else {
    const versionMatch = /[-@](\d+\.\d+\.\d+(?:[.-][\w]+)*)$/.exec(
      primaryToolName,
    );
    if (!versionMatch) {
      fail(
        "sbom_tool_version",
        `SBOM Tool element "${primaryToolName}" does not include a version.`,
      );
    }
  }

  // 9. SBOM Version
  const hasSbomVersion = annotations.some(
    (a) =>
      isNonEmptyString(a.statement) &&
      /^sbomVersion=[1-9]\d*$/.test(a.statement),
  );
  if (!hasSbomVersion) {
    fail(
      "sbom_version",
      "Missing SBOM Version annotation (sbomVersion=<positive-integer>).",
    );
  }

  // 10-16. Component Data fields
  if (packages.length === 0) {
    fail("component_name", "SBOM contains zero software_Package components.");
    fail("component_producer", "SBOM contains zero software_Package components.");
    fail("component_version", "SBOM contains zero software_Package components.");
    fail(
      "component_identifiers",
      "SBOM contains zero software_Package components.",
    );
    fail("component_hash_value", "SBOM contains zero software_Package components.");
    fail(
      "component_hash_algorithm",
      "SBOM contains zero software_Package components.",
    );
    fail("component_license", "SBOM contains zero software_Package components.");
  } else {
    const licensedIds = new Set<string>();
    for (const rel of relationships) {
      if (
        (rel.relationshipType === "hasDeclaredLicense" ||
          rel.relationshipType === "hasConcludedLicense") &&
        isNonEmptyString(rel.from) &&
        Array.isArray(rel.to) &&
        rel.to.length > 0
      ) {
        licensedIds.add(rel.from);
      }
    }

    for (const pkg of packages) {
      const label = pkg.spdxId ?? pkg.name ?? "<unnamed-package>";

      // 10. Component Producer
      const supplierNode = isNonEmptyString(pkg.suppliedBy)
        ? byId.get(pkg.suppliedBy)
        : undefined;
      if (!isNonEmptyString(supplierNode?.name)) {
        fail(
          "component_producer",
          `Package "${label}" is missing suppliedBy referencing a named Organization/Agent.`,
          label,
        );
      }

      // 11. Component Name
      if (!isNonEmptyString(pkg.name)) {
        fail("component_name", `Package "${label}" is missing name.`, label);
      }

      // 12. Component Version
      if (!isNonEmptyString(pkg.software_packageVersion)) {
        fail(
          "component_version",
          `Package "${label}" is missing software_packageVersion.`,
          label,
        );
      }

      // 13. Component Identifiers
      const hasId =
        isNonEmptyString(pkg.software_packageUrl) ||
        (Array.isArray(pkg.externalIdentifier) &&
          pkg.externalIdentifier.some((e) => isNonEmptyString(e.identifier)));
      if (!hasId) {
        fail(
          "component_identifiers",
          `Package "${label}" is missing a PURL or externalIdentifier.`,
          label,
        );
      }

      // 14 & 15. Component Hash Value & Algorithm
      const hashes = Array.isArray(pkg.verifiedUsing) ? pkg.verifiedUsing : [];
      const hasHashValue = hashes.some((h) => isNonEmptyString(h.hashValue));
      const hasHashAlgo = hashes.some((h) => isNonEmptyString(h.algorithm));
      if (!hasHashValue) {
        fail(
          "component_hash_value",
          `Package "${label}" is missing verifiedUsing[].hashValue.`,
          label,
        );
      }
      if (!hasHashAlgo) {
        fail(
          "component_hash_algorithm",
          `Package "${label}" is missing verifiedUsing[].algorithm.`,
          label,
        );
      }

      // 16. Component License
      if (!isNonEmptyString(pkg.spdxId) || !licensedIds.has(pkg.spdxId)) {
        fail(
          "component_license",
          `Package "${label}" is missing a hasDeclaredLicense or hasConcludedLicense relationship.`,
          label,
        );
      }
    }
  }

  // 17. Component Dependency Relationship
  const hasDependencyRel = relationships.some(
    (rel) =>
      (rel.relationshipType === "dependsOn" ||
        rel.relationshipType === "contains") &&
      isNonEmptyString(rel.from) &&
      Array.isArray(rel.to) &&
      rel.to.length > 0,
  );
  if (!hasDependencyRel) {
    fail(
      "component_dependency_relationship",
      "Missing component dependency relationships (dependsOn/contains) in SPDX @graph.",
    );
  }

  return finalizeReport("spdx-3.0", failures);
}

export function validateCycloneDx17(
  doc: CycloneDx17Document,
): ValidationReport {
  const failures: ValidationFailure[] = [];
  const fail = (
    element: Cisa2026Element,
    message: string,
    target?: string,
  ): void => {
    failures.push(target ? { element, message, target } : { element, message });
  };

  // 1. SBOM Author
  const authors = doc?.metadata?.authors ?? [];
  if (!authors.some((a) => isNonEmptyString(a?.name))) {
    fail("sbom_author", "Missing SBOM Author in metadata.authors[].name.");
  }

  // 2. SBOM Author Signature
  const hasEmbeddedSig =
    isNonEmptyString(doc?.signature?.algorithm) &&
    isNonEmptyString(doc?.signature?.value);
  const hasSigProp = (doc?.metadata?.properties ?? []).some(
    (p) =>
      p.name === "cisa:sbom:author-signature" && isNonEmptyString(p.value),
  );
  if (!hasEmbeddedSig && !hasSigProp) {
    fail(
      "sbom_author_signature",
      "Missing SBOM Author Signature (signature object or metadata property cisa:sbom:author-signature).",
    );
  }

  // 3. SBOM Data Format Name
  if (doc?.bomFormat !== "CycloneDX") {
    fail(
      "sbom_data_format_name",
      `bomFormat must be "CycloneDX", got "${String(doc?.bomFormat ?? "")}".`,
    );
  }

  // 4. SBOM Data Format Version
  if (doc?.specVersion !== "1.7") {
    fail(
      "sbom_data_format_version",
      `specVersion must be "1.7", got "${String(doc?.specVersion ?? "")}".`,
    );
  }

  // 5. SBOM Generation Context
  const lifecycles = doc?.metadata?.lifecycles ?? [];
  if (
    !lifecycles.some(
      (l) => isNonEmptyString(l?.phase) || isNonEmptyString(l?.name),
    )
  ) {
    fail(
      "sbom_generation_context",
      "Missing SBOM Generation Context in metadata.lifecycles.",
    );
  }

  // 6. SBOM Timestamp
  const timestamp = doc?.metadata?.timestamp;
  if (!isNonEmptyString(timestamp) || !RFC9557_TIMESTAMP.test(timestamp)) {
    fail(
      "sbom_timestamp",
      `metadata.timestamp must be an RFC 9557 / ISO 8601 timestamp, got "${String(timestamp ?? "")}".`,
    );
  }

  // 7 & 8. SBOM Tool Name & Tool Version
  const tools = doc?.metadata?.tools?.components ?? [];
  const validToolName = tools.some((t) => isNonEmptyString(t?.name));
  const validToolVersion = tools.some((t) => isNonEmptyString(t?.version));
  if (!validToolName) {
    fail(
      "sbom_tool_name",
      "Missing SBOM Tool Name in metadata.tools.components[].name.",
    );
  }
  if (!validToolVersion) {
    fail(
      "sbom_tool_version",
      "Missing SBOM Tool Version in metadata.tools.components[].version.",
    );
  }

  // 9. SBOM Version
  if (typeof doc?.version !== "number" || !Number.isInteger(doc.version) || doc.version < 1) {
    fail(
      "sbom_version",
      `SBOM version must be a positive integer, got "${String(doc?.version ?? "")}".`,
    );
  }

  // 10-16. Component Data fields (root component + all listed components)
  const allComponents = [
    ...(doc?.metadata?.component ? [doc.metadata.component] : []),
    ...(Array.isArray(doc?.components) ? doc.components : []),
  ];

  if (allComponents.length === 0) {
    fail("component_name", "SBOM contains zero components.");
    fail("component_producer", "SBOM contains zero components.");
    fail("component_version", "SBOM contains zero components.");
    fail("component_identifiers", "SBOM contains zero components.");
    fail("component_hash_value", "SBOM contains zero components.");
    fail("component_hash_algorithm", "SBOM contains zero components.");
    fail("component_license", "SBOM contains zero components.");
  } else {
    for (const comp of allComponents) {
      const label = comp["bom-ref"] ?? comp.name ?? "<unnamed-component>";

      // 10. Component Producer
      const hasProducer =
        isNonEmptyString(comp.supplier?.name) ||
        isNonEmptyString(comp.manufacturer?.name) ||
        isNonEmptyString(comp.author);
      if (!hasProducer) {
        fail(
          "component_producer",
          `Component "${label}" is missing supplier.name, manufacturer.name, or author.`,
          label,
        );
      }

      // 11. Component Name
      if (!isNonEmptyString(comp.name)) {
        fail("component_name", `Component "${label}" is missing name.`, label);
      }

      // 12. Component Version
      if (!isNonEmptyString(comp.version)) {
        fail(
          "component_version",
          `Component "${label}" is missing version.`,
          label,
        );
      }

      // 13. Component Identifiers
      const hasId = isNonEmptyString(comp.purl) || isNonEmptyString(comp.cpe);
      if (!hasId) {
        fail(
          "component_identifiers",
          `Component "${label}" is missing purl or cpe identifier.`,
          label,
        );
      }

      // 14 & 15. Component Hash Value & Algorithm
      const hashes = Array.isArray(comp.hashes) ? comp.hashes : [];
      if (!hashes.some((h) => isNonEmptyString(h.content))) {
        fail(
          "component_hash_value",
          `Component "${label}" is missing hashes[].content.`,
          label,
        );
      }
      if (!hashes.some((h) => isNonEmptyString(h.alg))) {
        fail(
          "component_hash_algorithm",
          `Component "${label}" is missing hashes[].alg.`,
          label,
        );
      }

      // 16. Component License
      const licenses = Array.isArray(comp.licenses) ? comp.licenses : [];
      const hasLicense = licenses.some(
        (l) =>
          isNonEmptyString(l.expression) ||
          isNonEmptyString(l.license?.id) ||
          isNonEmptyString(l.license?.name),
      );
      if (!hasLicense) {
        fail(
          "component_license",
          `Component "${label}" is missing licenses entry.`,
          label,
        );
      }
    }
  }

  // 17. Component Dependency Relationship
  const dependencies = Array.isArray(doc?.dependencies) ? doc.dependencies : [];
  if (
    dependencies.length === 0 ||
    !dependencies.some((d) => isNonEmptyString(d.ref))
  ) {
    fail(
      "component_dependency_relationship",
      "Missing component dependency relationships in dependencies[].",
    );
  }

  return finalizeReport("cyclonedx-1.7", failures);
}

export function formatValidationReport(report: ValidationReport): string {
  const status = report.valid ? "PASS" : "FAIL";
  const header = `[CISA 2026 ${report.format}] ${status} (${report.passed.length}/${report.checkedElements} elements satisfied)`;
  if (report.valid) {
    return header;
  }
  const lines = report.failures.map(
    (f) => `  - ${f.element}${f.target ? ` (${f.target})` : ""}: ${f.message}`,
  );
  return [header, ...lines].join("\n");
}
