const SHA256_HEX_REGEX = /^[0-9a-f]{64}$/;

export interface ChecksumEntry {
  /** Basename of the shipped file, as it will sit beside the checksums file. */
  name: string;
  /** Lowercase hex SHA-256 digest of the file contents. */
  sha256: string;
}

/**
 * Renders a release checksums file in GNU `sha256sum` text-mode format:
 * one `<hex-digest>  <filename>` line per shipped file (two spaces: the
 * separator plus the text-mode flag).
 *
 * The output is both verifiable with `sha256sum -c SHA256SUMS.txt` and
 * accepted verbatim as the `subject-checksums` input of
 * `actions/attest-build-provenance`, which turns every listed file into an
 * attested subject.
 */
export function buildChecksumsFile(entries: ChecksumEntry[]): string {
  const seen = new Set<string>();
  const sorted = [...entries].sort((a, b) => a.name.localeCompare(b.name));

  const lines: string[] = [];
  for (const entry of sorted) {
    if (entry.name.trim().length === 0) {
      throw new Error("Checksum entry must have a non-empty file name.");
    }
    if (!SHA256_HEX_REGEX.test(entry.sha256)) {
      throw new Error(
        `Checksum entry "${entry.name}" has an invalid SHA-256 digest "${entry.sha256}".`,
      );
    }
    if (seen.has(entry.name)) {
      throw new Error(`Duplicate checksum entry for "${entry.name}".`);
    }
    seen.add(entry.name);
    lines.push(`${entry.sha256}  ${entry.name}\n`);
  }

  return lines.join("");
}
