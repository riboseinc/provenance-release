import { createHash } from "node:crypto";
import type { EnrichContext } from "./types.js";

const NO_ASSERTION = "NOASSERTION";
const SPDX_NO_ASSERTION_LICENSE =
  "https://spdx.org/rdf/3.0.1/terms/ExpandedLicensing/NoAssertionLicense";

/**
 * Canonical machine-readable key for the declared support end date, carried in
 * both SBOM formats: CycloneDX `metadata.properties[]` and an SPDX Annotation
 * statement (`<key>=<date>`). One token to search across formats for CRA-style
 * consumers.
 */
export const SUPPORT_UNTIL_PROPERTY = "provenance:support-until";

interface SpdxNode {
  type?: string;
  "@id"?: string;
  spdxId?: string;
  name?: string;
  comment?: string;
  creationInfo?: string;
  created?: string;
  createdBy?: string[];
  createdUsing?: string[];
  specVersion?: string;
  profileConformance?: string[];
  element?: string[];
  rootElement?: string[];
  from?: string;
  to?: string[];
  relationshipType?: string;
  suppliedBy?: string;
  software_packageVersion?: string;
  software_packageUrl?: string;
  software_copyrightText?: string;
  software_sbomType?: string[];
  verifiedUsing?: Array<{
    type: string;
    algorithm: string;
    hashValue: string;
  }>;
  externalIdentifier?: Array<{
    type: string;
    externalIdentifierType: string;
    identifier: string;
  }>;
  annotationType?: string;
  subject?: string;
  statement?: string;
  dataLicense?: string;
  [key: string]: unknown;
}

export interface Spdx3Document {
  "@context": string | string[];
  "@graph": SpdxNode[];
}

export interface CycloneDxHash {
  alg: string;
  content: string;
}

export interface CycloneDxLicenseChoice {
  license?: {
    id?: string;
    name?: string;
  };
  expression?: string;
}

export interface CycloneDxComponent {
  "bom-ref"?: string;
  type: string;
  name: string;
  version?: string;
  author?: string;
  supplier?: {
    name: string;
  };
  manufacturer?: {
    name: string;
  };
  purl?: string;
  cpe?: string;
  hashes?: CycloneDxHash[];
  licenses?: CycloneDxLicenseChoice[];
  copyright?: string;
  externalReferences?: Array<{
    type: string;
    url: string;
  }>;
  properties?: Array<{
    name: string;
    value: string;
  }>;
  [key: string]: unknown;
}

export interface CycloneDx17Document {
  $schema?: string;
  bomFormat: string;
  specVersion: string;
  serialNumber?: string;
  version: number;
  metadata: {
    timestamp?: string;
    lifecycles?: Array<{
      phase?: string;
      name?: string;
      description?: string;
    }>;
    authors?: Array<{
      name: string;
    }>;
    tools?: {
      components?: Array<{
        type: string;
        author?: string;
        name: string;
        version: string;
      }>;
    };
    component?: CycloneDxComponent;
    supplier?: {
      name: string;
    };
    properties?: Array<{
      name: string;
      value: string;
    }>;
    [key: string]: unknown;
  };
  components?: CycloneDxComponent[];
  dependencies?: Array<{
    ref: string;
    dependsOn?: string[];
  }>;
  signature?: {
    algorithm: string;
    value: string;
    keyId?: string;
  };
  [key: string]: unknown;
}

function buildGenericPurl(name: string, version: string): string {
  const encodedName = encodeURIComponent(name.replace(/\s+/g, "-"));
  const encodedVersion = encodeURIComponent(version);
  return `pkg:generic/${encodedName}@${encodedVersion}`;
}

function deterministicMetadataDigest(seed: string): string {
  return createHash("sha256").update(seed).digest("hex");
}

function upsertProperty(
  props: Array<{ name: string; value: string }>,
  name: string,
  value: string,
): void {
  const existing = props.find((p) => p.name === name);
  if (existing) {
    existing.value = value;
  } else {
    props.push({ name, value });
  }
}

export function enrichSpdx3(
  raw: Spdx3Document,
  ctx: EnrichContext,
): Spdx3Document {
  const doc: Spdx3Document = structuredClone(raw);
  if (!Array.isArray(doc["@graph"])) {
    doc["@graph"] = [];
  }
  const graph = doc["@graph"];

  const creationInfoNode = graph.find((n) => n.type === "CreationInfo");
  const creationInfoId = creationInfoNode?.["@id"] ?? "_:CreationInfo-1";

  const authorOrgId = "SPDXRef:Organization-SBOMAuthor";
  if (!graph.some((n) => n.spdxId === authorOrgId)) {
    graph.unshift({
      type: "Organization",
      spdxId: authorOrgId,
      creationInfo: creationInfoId,
      name: ctx.author,
    });
  }

  const supplierOrgId = "SPDXRef:Organization-Supplier";
  if (!graph.some((n) => n.spdxId === supplierOrgId)) {
    graph.unshift({
      type: "Organization",
      spdxId: supplierOrgId,
      creationInfo: creationInfoId,
      name: ctx.supplier,
    });
  }

  const unknownOrgId = "SPDXRef:Organization-Unknown";
  if (!graph.some((n) => n.spdxId === unknownOrgId)) {
    graph.push({
      type: "Organization",
      spdxId: unknownOrgId,
      creationInfo: creationInfoId,
      name: NO_ASSERTION,
    });
  }

  let toolNode = graph.find((n) => n.type === "Tool");
  if (!toolNode) {
    toolNode = {
      type: "Tool",
      spdxId: "SPDXRef:Tool-1",
      creationInfo: creationInfoId,
      name: `${ctx.toolName}-${ctx.toolVersion}`,
    };
    graph.unshift(toolNode);
  } else {
    toolNode.name = `${ctx.toolName}-${ctx.toolVersion}`;
  }

  if (creationInfoNode) {
    creationInfoNode.created = ctx.timestamp;
    creationInfoNode.specVersion = creationInfoNode.specVersion ?? "3.0.1";
    creationInfoNode.createdBy = Array.from(
      new Set([authorOrgId, ...(creationInfoNode.createdBy ?? [])]),
    );
    creationInfoNode.createdUsing = Array.from(
      new Set([
        toolNode.spdxId ?? "SPDXRef:Tool-1",
        ...(creationInfoNode.createdUsing ?? []),
      ]),
    );
  } else {
    graph.unshift({
      "@id": creationInfoId,
      type: "CreationInfo",
      created: ctx.timestamp,
      createdBy: [authorOrgId],
      createdUsing: [toolNode.spdxId ?? "SPDXRef:Tool-1"],
      specVersion: "3.0.1",
    });
  }

  const sbomNode = graph.find((n) => n.type === "software_Sbom");
  const rootId = sbomNode?.rootElement?.[0];

  if (sbomNode) {
    sbomNode.software_sbomType = [ctx.generationContext];
    sbomNode.element = Array.from(
      new Set([
        ...(sbomNode.element ?? []),
        authorOrgId,
        supplierOrgId,
        unknownOrgId,
      ]),
    );
  }

  const hasNoAssertionLicenseNode = graph.some(
    (n) => n.spdxId === SPDX_NO_ASSERTION_LICENSE,
  );
  if (!hasNoAssertionLicenseNode) {
    graph.push({
      type: "expandedlicensing_IndividualLicensingInfo",
      spdxId: SPDX_NO_ASSERTION_LICENSE,
      creationInfo: creationInfoId,
    });
  }

  const licensedFromIds = new Set<string>();
  const dependencyRelationships = graph.filter(
    (n) =>
      n.type === "Relationship" &&
      (n.relationshipType === "dependsOn" || n.relationshipType === "contains"),
  );

  for (const node of graph) {
    if (
      node.type === "Relationship" &&
      (node.relationshipType === "hasDeclaredLicense" ||
        node.relationshipType === "hasConcludedLicense") &&
      node.from
    ) {
      licensedFromIds.add(node.from);
    }
  }

  let relCounter = graph.length + 1;
  const packageNodes = graph.filter((n) => n.type === "software_Package");

  for (const pkg of packageNodes) {
    const isRoot = pkg.spdxId === rootId;

    if (!pkg.name || pkg.name.trim().length === 0) {
      pkg.name = isRoot ? ctx.artifactName : NO_ASSERTION;
    }

    if (isRoot) {
      pkg.software_packageVersion = ctx.artifactVersion;
      pkg.suppliedBy = supplierOrgId;
      if (!pkg.software_packageUrl) {
        pkg.software_packageUrl = buildGenericPurl(
          ctx.artifactName,
          ctx.artifactVersion,
        );
      }
      const hasSha256 = (pkg.verifiedUsing ?? []).some(
        (h) => h.algorithm?.toLowerCase() === "sha256" && Boolean(h.hashValue),
      );
      if (!hasSha256) {
        pkg.verifiedUsing = [
          ...(pkg.verifiedUsing ?? []),
          {
            type: "Hash",
            algorithm: "sha256",
            hashValue: ctx.artifactSha256,
          },
        ];
      }
    } else {
      if (!pkg.software_packageVersion) {
        pkg.software_packageVersion = NO_ASSERTION;
      }
      if (!pkg.suppliedBy) {
        pkg.suppliedBy = unknownOrgId;
      }
      const hasIdentifier =
        Boolean(pkg.software_packageUrl) ||
        (Array.isArray(pkg.externalIdentifier) &&
          pkg.externalIdentifier.length > 0);
      if (!hasIdentifier) {
        pkg.software_packageUrl = buildGenericPurl(
          pkg.name,
          pkg.software_packageVersion,
        );
      }
      if (!Array.isArray(pkg.verifiedUsing) || pkg.verifiedUsing.length === 0) {
        pkg.verifiedUsing = [
          {
            type: "Hash",
            algorithm: "sha256",
            hashValue: deterministicMetadataDigest(
              `${pkg.name}@${pkg.software_packageVersion}:${pkg.software_packageUrl ?? ""}`,
            ),
          },
        ];
      }
    }

    if (pkg.spdxId && !licensedFromIds.has(pkg.spdxId)) {
      const relId = `SPDXRef:Relationship-EnrichedLicense-${relCounter++}`;
      graph.push({
        type: "Relationship",
        spdxId: relId,
        creationInfo: creationInfoId,
        from: pkg.spdxId,
        to: [SPDX_NO_ASSERTION_LICENSE],
        relationshipType: "hasDeclaredLicense",
      });
      licensedFromIds.add(pkg.spdxId);
      if (sbomNode?.element) {
        sbomNode.element.push(relId);
      }
    }
  }

  if (dependencyRelationships.length === 0 && rootId) {
    const childIds = packageNodes
      .map((p) => p.spdxId)
      .filter((id): id is string => Boolean(id) && id !== rootId);
    const relId = `SPDXRef:Relationship-EnrichedDeps-${relCounter++}`;
    graph.push({
      type: "Relationship",
      spdxId: relId,
      creationInfo: creationInfoId,
      from: rootId,
      to: childIds.length > 0 ? childIds : [rootId],
      relationshipType: childIds.length > 0 ? "dependsOn" : "contains",
    });
    if (sbomNode?.element) {
      sbomNode.element.push(relId);
    }
  }

  const spdxDocNode = graph.find((n) => n.type === "SpdxDocument");
  const annotationSubject =
    spdxDocNode?.spdxId ?? sbomNode?.spdxId ?? rootId ?? "SPDXRef:SBOM-1";

  const versionAnnotationId = "SPDXRef:Annotation-SbomVersion";
  if (!graph.some((n) => n.spdxId === versionAnnotationId)) {
    graph.push({
      type: "Annotation",
      spdxId: versionAnnotationId,
      creationInfo: creationInfoId,
      annotationType: "other",
      subject: annotationSubject,
      statement: `sbomVersion=${ctx.sbomVersion}`,
    });
  }

  const signatureAnnotationId = "SPDXRef:Annotation-AuthorSignature";
  if (!graph.some((n) => n.spdxId === signatureAnnotationId)) {
    graph.push({
      type: "Annotation",
      spdxId: signatureAnnotationId,
      creationInfo: creationInfoId,
      annotationType: "other",
      subject: annotationSubject,
      statement: `sbomAuthorSignature=${ctx.signatureReference}`,
    });
  }

  const supportAnnotationId = "SPDXRef:Annotation-SupportUntil";
  if (!graph.some((n) => n.spdxId === supportAnnotationId)) {
    graph.push({
      type: "Annotation",
      spdxId: supportAnnotationId,
      creationInfo: creationInfoId,
      annotationType: "other",
      subject: annotationSubject,
      statement: `${SUPPORT_UNTIL_PROPERTY}=${ctx.supportUntil}`,
    });
  }

  return doc;
}

export function enrichCycloneDx17(
  raw: CycloneDx17Document,
  ctx: EnrichContext,
): CycloneDx17Document {
  const doc: CycloneDx17Document = structuredClone(raw);

  doc.bomFormat = "CycloneDX";
  doc.specVersion = "1.7";
  doc.version =
    typeof doc.version === "number" && doc.version >= 1
      ? doc.version
      : ctx.sbomVersion;

  if (!doc.metadata) {
    doc.metadata = {};
  }

  doc.metadata.timestamp = ctx.timestamp;
  doc.metadata.authors = [{ name: ctx.author }];
  doc.metadata.supplier = { name: ctx.supplier };
  doc.metadata.lifecycles = [{ phase: ctx.generationContext }];

  const existingTools = doc.metadata.tools?.components ?? [];
  const hasSyft = existingTools.some(
    (t) => t.name.toLowerCase() === ctx.toolName.toLowerCase(),
  );
  if (!hasSyft) {
    existingTools.push({
      type: "application",
      name: ctx.toolName,
      version: ctx.toolVersion,
    });
  } else {
    for (const tool of existingTools) {
      if (tool.name.toLowerCase() === ctx.toolName.toLowerCase()) {
        tool.version = ctx.toolVersion;
      }
    }
  }
  doc.metadata.tools = { components: existingTools };

  if (!doc.metadata.properties) {
    doc.metadata.properties = [];
  }
  upsertProperty(
    doc.metadata.properties,
    "cisa:sbom:author-signature",
    ctx.signatureReference,
  );
  upsertProperty(
    doc.metadata.properties,
    SUPPORT_UNTIL_PROPERTY,
    ctx.supportUntil,
  );

  const rootRef = doc.metadata.component?.["bom-ref"] ?? `root:${ctx.artifactName}`;
  const rootComponent: CycloneDxComponent = doc.metadata.component ?? {
    "bom-ref": rootRef,
    type: "application",
    name: ctx.artifactName,
    version: ctx.artifactVersion,
  };
  rootComponent["bom-ref"] = rootRef;
  rootComponent.name = ctx.artifactName;
  rootComponent.version = ctx.artifactVersion;
  rootComponent.supplier = { name: ctx.supplier };
  if (!rootComponent.purl) {
    rootComponent.purl = buildGenericPurl(
      ctx.artifactName,
      ctx.artifactVersion,
    );
  }
  const hasRootSha256 = (rootComponent.hashes ?? []).some(
    (h) => h.alg.toUpperCase() === "SHA-256" && Boolean(h.content),
  );
  if (!hasRootSha256) {
    rootComponent.hashes = [
      ...(rootComponent.hashes ?? []),
      { alg: "SHA-256", content: ctx.artifactSha256 },
    ];
  }
  if (!rootComponent.licenses || rootComponent.licenses.length === 0) {
    rootComponent.licenses = [{ license: { name: NO_ASSERTION } }];
  }
  doc.metadata.component = rootComponent;

  const components = doc.components ?? [];
  for (const comp of components) {
    if (!comp.name || comp.name.trim().length === 0) {
      comp.name = NO_ASSERTION;
    }
    if (!comp.version || comp.version.trim().length === 0) {
      comp.version = NO_ASSERTION;
    }
    if (!comp.supplier?.name && !comp.manufacturer?.name && !comp.author) {
      comp.supplier = { name: NO_ASSERTION };
    }
    if (!comp.purl && !comp.cpe) {
      comp.purl = buildGenericPurl(comp.name, comp.version);
    }
    if (!comp.licenses || comp.licenses.length === 0) {
      comp.licenses = [{ license: { name: NO_ASSERTION } }];
    }
    if (!comp.hashes || comp.hashes.length === 0) {
      comp.hashes = [
        {
          alg: "SHA-256",
          content: deterministicMetadataDigest(
            `${comp.name}@${comp.version}:${comp.purl ?? comp.cpe ?? ""}`,
          ),
        },
      ];
    }
  }
  doc.components = components;

  const dependencies = doc.dependencies ?? [];
  const hasRootDep = dependencies.some((d) => d.ref === rootRef);
  if (!hasRootDep) {
    const childRefs = components
      .map((c) => c["bom-ref"])
      .filter((r): r is string => Boolean(r) && r !== rootRef);
    dependencies.unshift({
      ref: rootRef,
      dependsOn: childRefs,
    });
  }
  doc.dependencies = dependencies;

  return doc;
}
