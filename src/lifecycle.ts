import type { AttestationStatus, LifecycleDocument } from "./types.js";

export const SUPPORT_PERIOD_START_MARKER =
  "<!-- provenance:support-period:start -->";
export const SUPPORT_PERIOD_END_MARKER =
  "<!-- provenance:support-period:end -->";

const ISO_DATE_PATTERN = /^(\d{4})-(\d{2})-(\d{2})$/;

export function validateSupportUntil(value: string): string {
  const trimmed = value.trim();
  const match = ISO_DATE_PATTERN.exec(trimmed);
  if (!match) {
    throw new Error(
      `Invalid support-until date "${value}". Expected strict YYYY-MM-DD format.`,
    );
  }

  const year = Number.parseInt(match[1]!, 10);
  const month = Number.parseInt(match[2]!, 10);
  const day = Number.parseInt(match[3]!, 10);

  if (month < 1 || month > 12 || day < 1 || day > 31) {
    throw new Error(
      `Invalid support-until calendar date "${value}". Expected a real YYYY-MM-DD date.`,
    );
  }

  const utcDate = new Date(Date.UTC(year, month - 1, day));
  if (
    utcDate.getUTCFullYear() !== year ||
    utcDate.getUTCMonth() !== month - 1 ||
    utcDate.getUTCDate() !== day
  ) {
    throw new Error(
      `Invalid support-until calendar date "${value}". The specified date does not exist.`,
    );
  }

  return trimmed;
}

export function resolveAttestationStatus(
  attest: boolean,
  isPrivateRepo: boolean,
): AttestationStatus {
  if (!attest) {
    return "disabled";
  }
  if (isPrivateRepo) {
    return "skipped-private-repo";
  }
  return "attested";
}

export function buildLifecycleDocument(params: {
  repository: string;
  releaseTag: string;
  supportUntil: string;
  author: string;
  attest: boolean;
  isPrivateRepo: boolean;
  publishedAt?: string;
}): LifecycleDocument {
  const supportUntil = validateSupportUntil(params.supportUntil);
  const status = resolveAttestationStatus(params.attest, params.isPrivateRepo);

  return {
    schemaVersion: "1.0",
    repository: params.repository,
    releaseTag: params.releaseTag,
    supportUntil,
    publishedAt: params.publishedAt ?? new Date().toISOString(),
    author: params.author,
    attestation: {
      enabled: status === "attested",
      status,
    },
  };
}

export function renderSupportPeriodSection(params: {
  supportUntil: string;
  releaseTag: string;
  repository: string;
  attestationStatus: AttestationStatus;
}): string {
  const supportUntil = validateSupportUntil(params.supportUntil);
  const attestationLine =
    params.attestationStatus === "attested"
      ? `Build provenance for this release is keylessly signed with Sigstore and can be verified with \`gh attestation verify <artifact> -R ${params.repository}\`.`
      : params.attestationStatus === "skipped-private-repo"
        ? "Build provenance attestation was skipped automatically because this repository is private."
        : "Build provenance attestation was disabled for this release.";

  return [
    SUPPORT_PERIOD_START_MARKER,
    "## Support Period and Provenance",
    "",
    `This release (\`${params.releaseTag}\`) is supported until **${supportUntil}** (UTC).`,
    "The machine-readable lifecycle record is attached to this release as `lifecycle.json`, alongside SPDX 3.0 (`*.spdx.json`), CycloneDX 1.7 (`*.cdx.json`), an OpenVEX statement set (`openvex.json`), `NOTICE`, and the release checksums (`SHA256SUMS.txt`). The declared support date is also carried as the structured `provenance:support-until` property in both SBOM formats.",
    `The checksums file is itself attested; verify the entire release with \`gh attestation verify SHA256SUMS.txt -R ${params.repository}\`.`,
    attestationLine,
    SUPPORT_PERIOD_END_MARKER,
  ].join("\n");
}

/**
 * Appends or replaces the support-period section in GitHub Release notes.
 * Running this function repeatedly with the same inputs produces identical output.
 */
export function stampReleaseNotes(
  existingBody: string,
  params: {
    supportUntil: string;
    releaseTag: string;
    repository: string;
    attestationStatus: AttestationStatus;
  },
): string {
  const section = renderSupportPeriodSection(params);
  const normalizedBody = existingBody.replace(/\r\n/g, "\n");

  const startIdx = normalizedBody.indexOf(SUPPORT_PERIOD_START_MARKER);
  const endIdx = normalizedBody.indexOf(SUPPORT_PERIOD_END_MARKER);

  if (startIdx !== -1 && endIdx !== -1 && endIdx > startIdx) {
    const before = normalizedBody.slice(0, startIdx).trimEnd();
    const after = normalizedBody
      .slice(endIdx + SUPPORT_PERIOD_END_MARKER.length)
      .trimStart();

    const parts: string[] = [];
    if (before.length > 0) parts.push(before);
    parts.push(section);
    if (after.length > 0) parts.push(after);
    return `${parts.join("\n\n")}\n`;
  }

  const trimmed = normalizedBody.trimEnd();
  if (trimmed.length === 0) {
    return `${section}\n`;
  }
  return `${trimmed}\n\n${section}\n`;
}
