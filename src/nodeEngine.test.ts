import { describe, expect, it } from 'vitest';
import { isNodeEngineTargetCompatible } from './nodeEngine';

describe('isNodeEngineTargetCompatible', () => {
  it('honors comparator-only node engine ranges', () => {
    expect(isNodeEngineTargetCompatible('>=18', 20)).toBe(true);
    expect(isNodeEngineTargetCompatible('<20', 20)).toBe(false);
    expect(isNodeEngineTargetCompatible('>18', 18)).toBe(true);
    expect(isNodeEngineTargetCompatible('<=18', 19)).toBe(false);
    expect(isNodeEngineTargetCompatible('^18 || >=20', 20)).toBe(true);
    expect(isNodeEngineTargetCompatible('>18.10.0 <18.12.0', 18)).toBe(true);
  });

  it('treats bare versions as major-compatible ranges', () => {
    for (const range of ['18', '18.17', '18.17.0']) {
      expect(isNodeEngineTargetCompatible(range, 18)).toBe(true);
      expect(isNodeEngineTargetCompatible(range, 19)).toBe(false);
    }
  });
});
