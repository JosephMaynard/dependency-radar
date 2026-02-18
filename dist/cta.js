"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.CTA_BASE_URL = void 0;
exports.buildCtaUrl = buildCtaUrl;
exports.CTA_BASE_URL = 'https://dependency-radar.com/?source=standalone-report';
function buildCtaUrl(version) {
    const normalizedVersion = typeof version === 'string' && version.trim().length > 0
        ? version.trim()
        : 'unknown';
    return `${exports.CTA_BASE_URL}&cli=${encodeURIComponent(normalizedVersion)}`;
}
