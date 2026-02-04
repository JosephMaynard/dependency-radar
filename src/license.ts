import { SPDX_LICENSE_IDS, SPDX_DEPRECATED_LICENSE_IDS, SPDX_EXCEPTION_IDS, SPDX_DEPRECATED_EXCEPTION_IDS } from './generated/spdx';

export type LicenseConfidence = 'high' | 'medium' | 'low';

export interface SpdxValidationResult {
  valid: boolean;
  expression: boolean;
  deprecated: boolean;
  normalized: string;
  licenseIds: string[];
  exceptions: Array<{ id: string; deprecated: boolean; valid: boolean }>;
}

const LICENSE_ID_LOOKUP = new Map<string, string>();
const EXCEPTION_ID_LOOKUP = new Map<string, string>();

for (const id of SPDX_LICENSE_IDS) {
  LICENSE_ID_LOOKUP.set(id.toLowerCase(), id);
}
for (const id of SPDX_DEPRECATED_LICENSE_IDS) {
  if (!LICENSE_ID_LOOKUP.has(id.toLowerCase())) {
    LICENSE_ID_LOOKUP.set(id.toLowerCase(), id);
  }
}
for (const id of SPDX_EXCEPTION_IDS) {
  EXCEPTION_ID_LOOKUP.set(id.toLowerCase(), id);
}
for (const id of SPDX_DEPRECATED_EXCEPTION_IDS) {
  if (!EXCEPTION_ID_LOOKUP.has(id.toLowerCase())) {
    EXCEPTION_ID_LOOKUP.set(id.toLowerCase(), id);
  }
}

function normalizeSpdxId(raw: string): string | undefined {
  const trimmed = raw.trim();
  if (!trimmed) return undefined;
  if (SPDX_LICENSE_IDS.has(trimmed) || SPDX_DEPRECATED_LICENSE_IDS.has(trimmed)) return trimmed;
  return LICENSE_ID_LOOKUP.get(trimmed.toLowerCase());
}

function normalizeExceptionId(raw: string): string | undefined {
  const trimmed = raw.trim();
  if (!trimmed) return undefined;
  if (SPDX_EXCEPTION_IDS.has(trimmed) || SPDX_DEPRECATED_EXCEPTION_IDS.has(trimmed)) return trimmed;
  return EXCEPTION_ID_LOOKUP.get(trimmed.toLowerCase());
}

export function validateSpdxExpression(input: string): SpdxValidationResult {
  const invalid = {
    valid: false,
    expression: false,
    deprecated: false,
    normalized: input.trim(),
    licenseIds: [],
    exceptions: []
  };
  if (!input || typeof input !== 'string') return invalid;
  const raw = input.trim();
  if (!raw) return invalid;
  if (raw.includes('(') || raw.includes(')')) return invalid;

  const tokens = raw.split(/\s+/).filter(Boolean);
  if (tokens.length === 0) return invalid;

  const licenseIds: string[] = [];
  const exceptions: Array<{ id: string; deprecated: boolean; valid: boolean }> = [];
  const normalizedTokens: string[] = [];
  let deprecated = false;
  let expectTerm = true;

  let i = 0;
  while (i < tokens.length) {
    const token = tokens[i];
    if (expectTerm) {
      const licenseId = normalizeSpdxId(token);
      if (!licenseId) return invalid;
      const isDeprecated = SPDX_DEPRECATED_LICENSE_IDS.has(licenseId);
      if (isDeprecated) deprecated = true;
      licenseIds.push(licenseId);
      normalizedTokens.push(licenseId);
      i += 1;

      if (tokens[i] && tokens[i].toUpperCase() === 'WITH') {
        const exceptionToken = tokens[i + 1];
        if (!exceptionToken) return invalid;
        const exceptionId = normalizeExceptionId(exceptionToken);
        if (!exceptionId) {
          exceptions.push({ id: exceptionToken, deprecated: false, valid: false });
          return invalid;
        }
        const exceptionDeprecated = SPDX_DEPRECATED_EXCEPTION_IDS.has(exceptionId);
        if (exceptionDeprecated) deprecated = true;
        exceptions.push({ id: exceptionId, deprecated: exceptionDeprecated, valid: true });
        normalizedTokens.push('WITH', exceptionId);
        i += 2;
      }
      expectTerm = false;
      continue;
    }

    const op = token.toUpperCase();
    if (op !== 'AND' && op !== 'OR') return invalid;
    normalizedTokens.push(op);
    i += 1;
    expectTerm = true;
  }

  if (expectTerm) return invalid;

  return {
    valid: true,
    expression: normalizedTokens.includes('AND') || normalizedTokens.includes('OR'),
    deprecated,
    normalized: normalizedTokens.join(' '),
    licenseIds,
    exceptions
  };
}

function normalizeTextForMatch(text: string): string {
  return text
    .replace(/\r\n/g, '\n')
    .replace(/\r/g, '\n')
    .split('\n')
    .filter((line) => !/^copyright\b/i.test(line.trim()))
    .join('\n')
    .toLowerCase()
    .replace(/[ \t]+/g, ' ')
    .replace(/\n+/g, '\n')
    .trim();
}

function scoreMatch(text: string, phrases: string[]): number {
  let score = 0;
  for (const phrase of phrases) {
    if (text.includes(phrase)) score += 1;
  }
  return score;
}

function confidenceFromScore(score: number, total: number): LicenseConfidence | undefined {
  if (score === 0) return undefined;
  if (score === total) return 'high';
  if (score >= Math.max(2, Math.ceil(total * 0.6))) return 'medium';
  return 'low';
}

type InferenceMatch = { spdxId: string; confidence: LicenseConfidence };

const MIT_PHRASES = [
  'permission is hereby granted, free of charge, to any person obtaining a copy',
  'the software is provided "as is"',
  'in no event shall the authors or copyright holders'
];

const ISC_PHRASES = [
  'permission to use, copy, modify, and/or distribute this software for any purpose',
  'the software is provided "as is"'
];

const APACHE_PHRASES = [
  'apache license',
  'version 2.0',
  'http://www.apache.org/licenses/',
  'unless required by applicable law or agreed to in writing'
];

const BSD_COMMON = [
  'redistribution and use in source and binary forms',
  'this list of conditions and the following disclaimer'
];
const BSD_3_CLAUSE = [
  ...BSD_COMMON,
  'neither the name of'
];
const BSD_2_CLAUSE = BSD_COMMON;

const MPL_PHRASES = ['mozilla public license', 'version 2.0'];

const GPL_PHRASES = ['gnu general public license'];
const LGPL_PHRASES = ['gnu lesser general public license'];
const AGPL_PHRASES = ['gnu affero general public license'];

const GPL_LATER_PHRASE = 'either version';
const GPL_LATER_PHRASE_SUFFIX = 'any later version';

const UNLICENSE_PHRASES = [
  'this is free and unencumbered software released into the public domain',
  'the software is provided "as is"'
];

const CC0_PHRASES = ['creative commons zero', 'cc0 1.0'];

export function inferLicenseFromText(rawText: string): InferenceMatch | undefined {
  if (!rawText) return undefined;
  const text = normalizeTextForMatch(rawText);
  if (!text) return undefined;

  const candidates: InferenceMatch[] = [];

  const mitScore = scoreMatch(text, MIT_PHRASES);
  const mitConfidence = confidenceFromScore(mitScore, MIT_PHRASES.length);
  if (mitConfidence) candidates.push({ spdxId: 'MIT', confidence: mitConfidence });

  const iscScore = scoreMatch(text, ISC_PHRASES);
  const iscConfidence = confidenceFromScore(iscScore, ISC_PHRASES.length);
  if (iscConfidence) candidates.push({ spdxId: 'ISC', confidence: iscConfidence });

  const apacheScore = scoreMatch(text, APACHE_PHRASES);
  const apacheConfidence = confidenceFromScore(apacheScore, APACHE_PHRASES.length);
  if (apacheConfidence) candidates.push({ spdxId: 'Apache-2.0', confidence: apacheConfidence });

  const bsd3Score = scoreMatch(text, BSD_3_CLAUSE);
  const bsd3Confidence = confidenceFromScore(bsd3Score, BSD_3_CLAUSE.length);
  if (bsd3Confidence) {
    candidates.push({ spdxId: 'BSD-3-Clause', confidence: bsd3Confidence });
  } else {
    const bsd2Score = scoreMatch(text, BSD_2_CLAUSE);
    const bsd2Confidence = confidenceFromScore(bsd2Score, BSD_2_CLAUSE.length);
    if (bsd2Confidence) candidates.push({ spdxId: 'BSD-2-Clause', confidence: bsd2Confidence });
  }

  const mplScore = scoreMatch(text, MPL_PHRASES);
  const mplConfidence = confidenceFromScore(mplScore, MPL_PHRASES.length);
  if (mplConfidence) candidates.push({ spdxId: 'MPL-2.0', confidence: mplConfidence });

  const unlicenseScore = scoreMatch(text, UNLICENSE_PHRASES);
  const unlicenseConfidence = confidenceFromScore(unlicenseScore, UNLICENSE_PHRASES.length);
  if (unlicenseConfidence) candidates.push({ spdxId: 'Unlicense', confidence: unlicenseConfidence });

  const cc0Score = scoreMatch(text, CC0_PHRASES);
  const cc0Confidence = confidenceFromScore(cc0Score, CC0_PHRASES.length);
  if (cc0Confidence) candidates.push({ spdxId: 'CC0-1.0', confidence: cc0Confidence });

  if (text.includes('gnu')) {
    if (text.includes(AGPL_PHRASES[0])) {
      candidates.push({
        spdxId: text.includes(GPL_LATER_PHRASE) && text.includes(GPL_LATER_PHRASE_SUFFIX)
          ? 'AGPL-3.0-or-later'
          : 'AGPL-3.0-only',
        confidence: 'medium'
      });
    } else if (text.includes(LGPL_PHRASES[0])) {
      candidates.push({
        spdxId: text.includes('version 2.1')
          ? (text.includes(GPL_LATER_PHRASE) && text.includes(GPL_LATER_PHRASE_SUFFIX)
              ? 'LGPL-2.1-or-later'
              : 'LGPL-2.1-only')
          : (text.includes(GPL_LATER_PHRASE) && text.includes(GPL_LATER_PHRASE_SUFFIX)
              ? 'LGPL-3.0-or-later'
              : 'LGPL-3.0-only'),
        confidence: 'medium'
      });
    } else if (text.includes(GPL_PHRASES[0])) {
      const isVersion2 = text.includes('version 2');
      const isVersion3 = text.includes('version 3');
      const isLater = text.includes(GPL_LATER_PHRASE) && text.includes(GPL_LATER_PHRASE_SUFFIX);
      if (isVersion2) {
        candidates.push({ spdxId: isLater ? 'GPL-2.0-or-later' : 'GPL-2.0-only', confidence: 'medium' });
      } else if (isVersion3) {
        candidates.push({ spdxId: isLater ? 'GPL-3.0-or-later' : 'GPL-3.0-only', confidence: 'medium' });
      }
    }
  }

  if (candidates.length === 0) return undefined;
  const confidenceRank: Record<LicenseConfidence, number> = { high: 3, medium: 2, low: 1 };
  candidates.sort((a, b) => confidenceRank[b.confidence] - confidenceRank[a.confidence]);
  return candidates[0];
}

export function pickLicenseRisk(licenseIds: string[]): 'green' | 'amber' | 'red' {
  if (!licenseIds || licenseIds.length === 0) return 'red';
  const normalized = licenseIds.map((id) => id.toUpperCase());
  const green = ['MIT', 'BSD-2-CLAUSE', 'BSD-3-CLAUSE', 'APACHE-2.0', 'ISC', 'CC0-1.0', 'UNLICENSE'];
  const amber = ['LGPL', 'LGPL-2.1', 'LGPL-3.0', 'MPL', 'MPL-2.0'];
  let risk: 'green' | 'amber' | 'red' = 'green';
  for (const id of normalized) {
    if (green.includes(id)) continue;
    if (amber.some((prefix) => id.startsWith(prefix))) {
      if (risk === 'green') risk = 'amber';
      continue;
    }
    risk = 'red';
  }
  return risk;
}
