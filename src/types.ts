import type { OpenVexDocument } from "./vex.js";

export const CISA_2026_ELEMENTS = [
  "sbom_author",
  "sbom_author_signature",
  "sbom_data_format_name",
  "sbom_data_format_version",
  "sbom_generation_context",
  "sbom_timestamp",
  "sbom_tool_name",
  "sbom_tool_version",
  "sbom_version",
  "component_producer",
  "component_name",
  "component_version",
  "component_identifiers",
  "component_hash_value",
  "component_hash_algorithm",
  "component_license",
  "component_dependency_relationship",
] as const;

export type Cisa2026Element = (typeof CISA_2026_ELEMENTS)[number];

export type SbomFormat = "spdx-3.0" | "cyclonedx-1.7";

export type AttestationStatus =
  | "attested"
  | "skipped-private-repo"
  | "disabled";

export interface ValidationFailure {
  element: Cisa2026Element;
  message: string;
  target?: string;
}

export interface ValidationReport {
  valid: boolean;
  format: SbomFormat;
  checkedElements: number;
  passed: Cisa2026Element[];
  failures: ValidationFailure[];
}

export interface EnrichContext {
  artifactName: string;
  artifactVersion: string;
  artifactSha256: string;
  author: string;
  supplier: string;
  repository: string;
  supportUntil: string;
  generationContext: string;
  sbomVersion: number;
  toolName: string;
  toolVersion: string;
  timestamp: string;
  signatureReference: string;
}

export interface LifecycleDocument {
  schemaVersion: "1.0";
  repository: string;
  releaseTag: string;
  supportUntil: string;
  publishedAt: string;
  author: string;
  attestation: {
    enabled: boolean;
    status: AttestationStatus;
  };
}

export interface SyftPlatformSpec {
  filename: string;
  url: string;
  sha256: string;
}

export interface SyftManifest {
  tool: "syft";
  version: string;
  releaseUrl: string;
  checksumsUrl: string;
  platforms: Record<string, SyftPlatformSpec>;
}

export interface PinViolation {
  file: string;
  line?: number;
  rule: "action-sha-pin" | "binary-checksum-pin" | "no-hardcoded-instance";
  message: string;
}

export interface PinCheckResult {
  valid: boolean;
  checkedWorkflows: number;
  checkedBinaries: number;
  violations: PinViolation[];
}

export interface PipelineOptions {
  artifactsPath: string;
  outputDir: string;
  releaseTag: string;
  supportUntil: string;
  author: string;
  supplier?: string;
  repository: string;
  attest: boolean;
  isPrivateRepo?: boolean;
  syftBin?: string;
  repoRoot?: string;
}

export interface GeneratedArtifactOutputs {
  artifactName: string;
  artifactPath: string;
  artifactSha256: string;
  spdxPath: string;
  cdxPath: string;
  spdxValidation: ValidationReport;
  cdxValidation: ValidationReport;
}

export interface PipelineResult {
  artifacts: GeneratedArtifactOutputs[];
  noticePath: string;
  lifecyclePath: string;
  lifecycle: LifecycleDocument;
  openvexPath: string;
  openvex: OpenVexDocument;
  checksumsPath: string;
  syftVersion: string;
}
