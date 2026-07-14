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
    expect(result.expression).toBe(true);
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

  it('matches canonical ISC text when a fingerprint phrase wraps across lines', () => {
    const text = [
      'Permission to use, copy, modify,',
      'and/or distribute this software for any purpose with or without fee is hereby granted.',
      'THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES.'
    ].join('\n');
    expect(inferLicenseFromText(text)).toEqual({ spdxId: 'ISC', confidence: 'high' });
  });

  it('distinguishes canonical BSD-2-Clause and BSD-3-Clause text', () => {
    const common = [
      'Redistribution and use in source and binary forms, with or without modification, are permitted.',
      'Redistributions of source code must retain the above copyright notice,',
      'this list of conditions and the following disclaimer.'
    ];
    expect(inferLicenseFromText(common.join('\n'))).toEqual({
      spdxId: 'BSD-2-Clause',
      confidence: 'high'
    });
    expect(inferLicenseFromText([...common, 'Neither the name of Example nor the names of its contributors may be used.'].join('\n'))).toEqual({
      spdxId: 'BSD-3-Clause',
      confidence: 'high'
    });
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
