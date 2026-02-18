export const CTA_BASE_URL = 'https://dependency-radar.com/?source=standalone-report';

export function buildCtaUrl(version: string | undefined): string {
  const normalizedVersion = typeof version === 'string' && version.trim().length > 0
    ? version.trim()
    : 'unknown';
  return `${CTA_BASE_URL}&cli=${encodeURIComponent(normalizedVersion)}`;
}
