import { describe, expect, it } from 'vitest';
import { inferLicenseFromText, pickLicenseRisk, validateSpdxExpression } from './license';

describe('SPDX validation', () => {
  it('validates simple SPDX identifiers', () => {
    const result = validateSpdxExpression('MIT');
    expect(result.valid).toBe(true);
    expect(result.normalized).toBe('MIT');
    expect(result.expression).toBe(false);
  });

  it('validates SPDX expressions with exceptions', () => {
    const result = validateSpdxExpression('GPL-2.0-only WITH Classpath-exception-2.0');
    expect(result.valid).toBe(true);
    expect(result.expression).toBe(false);
    expect(result.exceptions).toContainEqual({ id: 'Classpath-exception-2.0', deprecated: false, valid: true });
  });

  it('rejects malformed SPDX expressions', () => {
    const result = validateSpdxExpression('MIT OR');
    expect(result.valid).toBe(false);
  });
});

describe('license inference', () => {
  it('infers MIT from canonical license text', () => {
    const text = [
      'Permission is hereby granted, free of charge, to any person obtaining a copy',
      'THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND'
    ].join('\n');
    const inferred = inferLicenseFromText(text);
    expect(inferred?.spdxId).toBe('MIT');
  });

  it('returns undefined for unrecognized text', () => {
    const inferred = inferLicenseFromText('this is not a license file');
    expect(inferred).toBeUndefined();
  });
});

describe('license risk mapping', () => {
  it('returns green for permissive licenses', () => {
    expect(pickLicenseRisk(['MIT'])).toBe('green');
  });

  it('returns amber for weak-copyleft licenses', () => {
    expect(pickLicenseRisk(['MPL-2.0'])).toBe('amber');
  });

  it('returns red for unknown/high-risk licenses', () => {
    expect(pickLicenseRisk(['LicenseRef-Proprietary'])).toBe('red');
  });
});
