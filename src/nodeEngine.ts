type VersionTuple = [number, number, number];

function parseVersion(value: string): VersionTuple | undefined {
  const match = value.trim().match(/^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?/);
  return match ? [Number(match[1]), Number(match[2] || 0), Number(match[3] || 0)] : undefined;
}

function compare(a: VersionTuple, b: VersionTuple): number {
  for (let i = 0; i < 3; i += 1) if (a[i] !== b[i]) return a[i] - b[i];
  return 0;
}

function satisfiesComparator(target: VersionTuple, comparator: string): boolean {
  const match = comparator.trim().match(/^(<=|>=|<|>|=)?\s*v?(\d+(?:\.\d+){0,2})/);
  if (!match) return true;
  const version = parseVersion(match[2]);
  if (!version) return true;
  const diff = compare(target, version);
  const op = match[1] || '=';
  if (op === '<') return diff < 0;
  if (op === '<=') return diff <= 0;
  if (op === '>') return diff > 0;
  if (op === '>=') return diff >= 0;
  return diff === 0;
}

function comparatorAllowsTargetMajor(comparator: string, minTarget: VersionTuple, maxTarget: VersionTuple): boolean {
  const match = comparator.trim().match(/^(<=|>=|<|>|=)?\s*v?(\d+(?:\.\d+){0,2})/);
  if (!match) return true;
  const version = parseVersion(match[2]);
  if (!version) return true;
  const op = match[1] || '=';
  if (op === '<') return compare(minTarget, version) < 0;
  if (op === '<=') return compare(minTarget, version) <= 0;
  if (op === '>') return compare(maxTarget, version) > 0;
  if (op === '>=') return compare(maxTarget, version) > 0;
  return compare(minTarget, version) <= 0 && compare(version, maxTarget) < 0;
}

function comparatorsOverlapTargetMajor(comparators: string[], targetMajor: number): boolean {
  const minTarget: VersionTuple = [targetMajor, 0, 0];
  const maxTarget: VersionTuple = [targetMajor + 1, 0, 0];
  if (!comparators.every((comparator) => comparatorAllowsTargetMajor(comparator, minTarget, maxTarget))) return false;
  return (
    comparators.every((comparator) => satisfiesComparator(minTarget, comparator)) ||
    comparators.every((comparator) => satisfiesComparator([targetMajor, 999, 999], comparator))
  );
}

function expandToken(token: string): string[] {
  const trimmed = token.trim();
  if (!trimmed || trimmed === '*' || /^[xX]$/.test(trimmed)) return [];
  const caret = trimmed.match(/^\^\s*v?(\d+)(?:\.(\d+))?(?:\.(\d+))?/);
  if (caret) {
    const major = Number(caret[1]);
    return [`>=${major}.${caret[2] || 0}.${caret[3] || 0}`, `<${major + 1}.0.0`];
  }
  const tilde = trimmed.match(/^~\s*v?(\d+)(?:\.(\d+))?(?:\.(\d+))?/);
  if (tilde) {
    const major = Number(tilde[1]);
    const minor = Number(tilde[2] || 0);
    return [`>=${major}.${minor}.${tilde[3] || 0}`, `<${major}.${minor + 1}.0`];
  }
  if (/^v?\d+(?:\.\d+){0,2}$/.test(trimmed)) {
    const [major] = parseVersion(trimmed)!;
    return [`>=${major}.0.0`, `<${major + 1}.0.0`];
  }
  return [trimmed];
}

export function isNodeEngineTargetCompatible(range: string | null | undefined, targetMajor: number): boolean | undefined {
  if (!range || !range.trim()) return undefined;
  const clauses = range.split('||').map((clause) => clause.trim()).filter(Boolean);
  if (clauses.length === 0) return undefined;
  return clauses.some((clause) => {
    const hyphen = clause.match(/^\s*v?(\d+(?:\.\d+){0,2})\s+-\s+v?(\d+(?:\.\d+){0,2})\s*$/);
    const tokens = hyphen ? [`>=${hyphen[1]}`, `<=${hyphen[2]}`] : clause.split(/\s+/);
    const comparators = tokens.flatMap(expandToken);
    return comparators.length === 0 || comparatorsOverlapTargetMajor(comparators, targetMajor);
  });
}
