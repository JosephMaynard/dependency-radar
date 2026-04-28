type VersionTuple = [number, number, number];

type ParsedVersion = {
  version: VersionTuple;
  parts: number;
};

function parseVersionParts(value: string): ParsedVersion | undefined {
  const match = value.trim().match(/^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?$/);
  if (!match) return undefined;
  return {
    version: [Number(match[1]), Number(match[2] || 0), Number(match[3] || 0)],
    parts: match[3] ? 3 : match[2] ? 2 : 1,
  };
}

function parseVersion(value: string): VersionTuple | undefined {
  return parseVersionParts(value)?.version;
}

function compare(a: VersionTuple, b: VersionTuple): number {
  for (let i = 0; i < 3; i += 1) if (a[i] !== b[i]) return a[i] - b[i];
  return 0;
}

function satisfiesComparator(target: VersionTuple, comparator: string): boolean {
  const match = comparator.trim().match(/^(<=|>=|<|>|=)?\s*v?(\d+(?:\.\d+){0,2})$/);
  if (!match) return false;
  const version = parseVersion(match[2]);
  if (!version) return false;
  const diff = compare(target, version);
  const op = match[1] || '=';
  if (op === '<') return diff < 0;
  if (op === '<=') return diff <= 0;
  if (op === '>') return diff > 0;
  if (op === '>=') return diff >= 0;
  return diff === 0;
}

function comparatorAllowsTargetMajor(comparator: string, minTarget: VersionTuple, maxTarget: VersionTuple): boolean {
  const bounds = boundsForComparator(comparator);
  return Boolean(bounds && intervalsOverlap(bounds, { lower: minTarget, lowerInclusive: true, upper: maxTarget, upperInclusive: false }));
}

type VersionInterval = {
  lower?: VersionTuple;
  lowerInclusive: boolean;
  upper?: VersionTuple;
  upperInclusive: boolean;
};

function boundsForComparator(comparator: string): VersionInterval | undefined {
  const match = comparator.trim().match(/^(<=|>=|<|>|=)?\s*v?(\d+(?:\.\d+){0,2})$/);
  if (!match) return undefined;
  const parsed = parseVersionParts(match[2]);
  if (!parsed) return undefined;
  const version = parsed.version;
  const nextMajor: VersionTuple = [version[0] + 1, 0, 0];
  const op = match[1] || '=';
  if (op === '<') return { lowerInclusive: true, upper: version, upperInclusive: false };
  if (op === '<=' && parsed.parts === 1) return { lowerInclusive: true, upper: nextMajor, upperInclusive: false };
  if (op === '<=') return { lowerInclusive: true, upper: version, upperInclusive: true };
  if (op === '>' && parsed.parts === 1) return { lower: nextMajor, lowerInclusive: true, upperInclusive: true };
  if (op === '>') return { lower: version, lowerInclusive: false, upperInclusive: true };
  if (op === '>=') return { lower: version, lowerInclusive: true, upperInclusive: true };
  return { lower: version, lowerInclusive: true, upper: version, upperInclusive: true };
}

function laterLower(a: VersionInterval, b: VersionInterval): Pick<VersionInterval, 'lower' | 'lowerInclusive'> {
  if (!a.lower) return { lower: b.lower, lowerInclusive: b.lowerInclusive };
  if (!b.lower) return { lower: a.lower, lowerInclusive: a.lowerInclusive };
  const diff = compare(a.lower, b.lower);
  if (diff > 0) return { lower: a.lower, lowerInclusive: a.lowerInclusive };
  if (diff < 0) return { lower: b.lower, lowerInclusive: b.lowerInclusive };
  return { lower: a.lower, lowerInclusive: a.lowerInclusive && b.lowerInclusive };
}

function earlierUpper(a: VersionInterval, b: VersionInterval): Pick<VersionInterval, 'upper' | 'upperInclusive'> {
  if (!a.upper) return { upper: b.upper, upperInclusive: b.upperInclusive };
  if (!b.upper) return { upper: a.upper, upperInclusive: a.upperInclusive };
  const diff = compare(a.upper, b.upper);
  if (diff < 0) return { upper: a.upper, upperInclusive: a.upperInclusive };
  if (diff > 0) return { upper: b.upper, upperInclusive: b.upperInclusive };
  return { upper: a.upper, upperInclusive: a.upperInclusive && b.upperInclusive };
}

function intervalsOverlap(a: VersionInterval, b: VersionInterval): boolean {
  const lower = laterLower(a, b);
  const upper = earlierUpper(a, b);
  if (!lower.lower || !upper.upper) return true;
  const diff = compare(lower.lower, upper.upper);
  if (diff < 0) return true;
  if (diff > 0) return false;
  return lower.lowerInclusive && upper.upperInclusive;
}

function comparatorsOverlapTargetMajor(comparators: string[], targetMajor: number): boolean {
  const target: VersionInterval = {
    lower: [targetMajor, 0, 0],
    lowerInclusive: true,
    upper: [targetMajor + 1, 0, 0],
    upperInclusive: false,
  };
  let interval: VersionInterval = {
    lowerInclusive: true,
    upperInclusive: true,
  };
  for (const comparator of comparators) {
    if (!comparatorAllowsTargetMajor(comparator, target.lower!, target.upper!)) return false;
    const bounds = boundsForComparator(comparator);
    if (!bounds) continue;
    const lower = laterLower(interval, bounds);
    const upper = earlierUpper(interval, bounds);
    interval = { ...lower, ...upper };
    if (!intervalsOverlap(interval, target)) return false;
  }
  return intervalsOverlap(interval, target);
}

function expandToken(token: string): string[] {
  const trimmed = token.trim();
  if (!trimmed || trimmed === '*' || /^[xX]$/.test(trimmed)) return [];
  const xRange = trimmed.match(/^v?(\d+)(?:\.(\d+|[xX*]))?(?:\.(\d+|[xX*]))?$/);
  if (xRange && (xRange[2]?.match(/^[xX*]$/) || xRange[3]?.match(/^[xX*]$/))) {
    const major = Number(xRange[1]);
    if (!xRange[2] || /^[xX*]$/.test(xRange[2])) return [`>=${major}.0.0`, `<${major + 1}.0.0`];
    const minor = Number(xRange[2]);
    return [`>=${major}.${minor}.0`, `<${major}.${minor + 1}.0`];
  }
  const caret = trimmed.match(/^\^\s*v?(\d+)(?:\.(\d+))?(?:\.(\d+))?$/);
  if (caret) {
    const major = Number(caret[1]);
    return [`>=${major}.${caret[2] || 0}.${caret[3] || 0}`, `<${major + 1}.0.0`];
  }
  const tilde = trimmed.match(/^~\s*v?(\d+)(?:\.(\d+))?(?:\.(\d+))?$/);
  if (tilde) {
    const major = Number(tilde[1]);
    if (!tilde[2]) return [`>=${major}.0.0`, `<${major + 1}.0.0`];
    const minor = Number(tilde[2]);
    return [`>=${major}.${minor}.${tilde[3] || 0}`, `<${major}.${minor + 1}.0`];
  }
  const bare = trimmed.match(/^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?$/);
  if (bare) {
    const major = Number(bare[1]);
    if (!bare[2]) return [`>=${major}.0.0`, `<${major + 1}.0.0`];
    const minor = Number(bare[2]);
    if (!bare[3]) return [`>=${major}.${minor}.0`, `<${major}.${minor + 1}.0`];
    return [`=${major}.${minor}.${bare[3]}`];
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
