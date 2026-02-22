export const CTA_BASE_URL = 'https://dependency-radar.com/next-steps?source=standalone-report';

/**
 * Builds a CTA URL that includes the CLI version as a `cli` query parameter.
 *
 * @param version - CLI version string to include; when `undefined`, empty, or whitespace-only, `unknown` is used
 * @returns The CTA URL with an appended `cli` query parameter whose value is the URI-encoded CLI version (or `unknown` when version is missing or empty)
 */
export function buildCtaUrl(version: string | undefined): string {
  const normalizedVersion = typeof version === 'string' && version.trim().length > 0
    ? version.trim()
    : 'unknown';
  return `${CTA_BASE_URL}&cli=${encodeURIComponent(normalizedVersion)}`;
}