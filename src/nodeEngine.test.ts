import { describe, expect, it } from 'vitest';
import { isNodeEngineTargetCompatible } from './nodeEngine';

describe('isNodeEngineTargetCompatible', () => {
  it('honors comparator-only node engine ranges', () => {
    expect(isNodeEngineTargetCompatible('>=18', 20)).toBe(true);
    expect(isNodeEngineTargetCompatible('<20', 20)).toBe(false);
    expect(isNodeEngineTargetCompatible('>18', 18)).toBe(false);
    expect(isNodeEngineTargetCompatible('>18', 19)).toBe(true);
    expect(isNodeEngineTargetCompatible('<=18', 18)).toBe(true);
    expect(isNodeEngineTargetCompatible('<=18', 19)).toBe(false);
    expect(isNodeEngineTargetCompatible('^18 || >=20', 20)).toBe(true);
    expect(isNodeEngineTargetCompatible('>18.10.0 <18.12.0', 18)).toBe(true);
  });

  it('handles x-ranges, tilde ranges, and bare versions', () => {
    for (const range of ['18.x', '18.*', '18.5.x', '~18', '~18.5', '18', '18.5', '18.5.1']) {
      expect(isNodeEngineTargetCompatible(range, 18)).toBe(true);
      expect(isNodeEngineTargetCompatible(range, 19)).toBe(false);
    }
  });

  it('fails closed for malformed comparator tokens', () => {
    expect(isNodeEngineTargetCompatible('>=18foo', 18)).toBe(false);
    expect(isNodeEngineTargetCompatible('18.0.0-beta', 18)).toBe(false);
    expect(isNodeEngineTargetCompatible('^18foo', 18)).toBe(false);
  });
});
