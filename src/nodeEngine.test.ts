import { describe, expect, it } from 'vitest';
import { isNodeEngineTargetCompatible } from './nodeEngine';

describe('isNodeEngineTargetCompatible', () => {
  it('honors comparator-only node engine ranges', () => {
    expect(isNodeEngineTargetCompatible('>=18', 20)).toBe(true);
    expect(isNodeEngineTargetCompatible('<20', 20)).toBe(false);
    expect(isNodeEngineTargetCompatible('>18', 18)).toBe(false);
    expect(isNodeEngineTargetCompatible('^18 || >=20', 20)).toBe(true);
  });
});
