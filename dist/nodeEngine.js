"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.isNodeEngineTargetCompatible = isNodeEngineTargetCompatible;
function parseVersion(value) {
    const match = value.trim().match(/^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?/);
    return match ? [Number(match[1]), Number(match[2] || 0), Number(match[3] || 0)] : undefined;
}
function compare(a, b) {
    for (let i = 0; i < 3; i += 1)
        if (a[i] !== b[i])
            return a[i] - b[i];
    return 0;
}
function satisfiesComparator(target, comparator) {
    const match = comparator.trim().match(/^(<=|>=|<|>|=)?\s*v?(\d+(?:\.\d+){0,2})/);
    if (!match)
        return true;
    const version = parseVersion(match[2]);
    if (!version)
        return true;
    const diff = compare(target, version);
    const op = match[1] || '=';
    if (op === '<')
        return diff < 0;
    if (op === '<=')
        return diff <= 0;
    if (op === '>')
        return diff > 0;
    if (op === '>=')
        return diff >= 0;
    return diff === 0;
}
function comparatorAllowsTargetMajor(comparator, minTarget, maxTarget) {
    const bounds = boundsForComparator(comparator);
    return !bounds || intervalsOverlap(bounds, { lower: minTarget, lowerInclusive: true, upper: maxTarget, upperInclusive: false });
}
function boundsForComparator(comparator) {
    const match = comparator.trim().match(/^(<=|>=|<|>|=)?\s*v?(\d+(?:\.\d+){0,2})/);
    if (!match)
        return undefined;
    const version = parseVersion(match[2]);
    if (!version)
        return undefined;
    const op = match[1] || '=';
    if (op === '<')
        return { lowerInclusive: true, upper: version, upperInclusive: false };
    if (op === '<=')
        return { lowerInclusive: true, upper: version, upperInclusive: true };
    if (op === '>')
        return { lower: version, lowerInclusive: false, upperInclusive: true };
    if (op === '>=')
        return { lower: version, lowerInclusive: true, upperInclusive: true };
    return { lower: version, lowerInclusive: true, upper: version, upperInclusive: true };
}
function laterLower(a, b) {
    if (!a.lower)
        return { lower: b.lower, lowerInclusive: b.lowerInclusive };
    if (!b.lower)
        return { lower: a.lower, lowerInclusive: a.lowerInclusive };
    const diff = compare(a.lower, b.lower);
    if (diff > 0)
        return { lower: a.lower, lowerInclusive: a.lowerInclusive };
    if (diff < 0)
        return { lower: b.lower, lowerInclusive: b.lowerInclusive };
    return { lower: a.lower, lowerInclusive: a.lowerInclusive && b.lowerInclusive };
}
function earlierUpper(a, b) {
    if (!a.upper)
        return { upper: b.upper, upperInclusive: b.upperInclusive };
    if (!b.upper)
        return { upper: a.upper, upperInclusive: a.upperInclusive };
    const diff = compare(a.upper, b.upper);
    if (diff < 0)
        return { upper: a.upper, upperInclusive: a.upperInclusive };
    if (diff > 0)
        return { upper: b.upper, upperInclusive: b.upperInclusive };
    return { upper: a.upper, upperInclusive: a.upperInclusive && b.upperInclusive };
}
function intervalsOverlap(a, b) {
    const lower = laterLower(a, b);
    const upper = earlierUpper(a, b);
    if (!lower.lower || !upper.upper)
        return true;
    const diff = compare(lower.lower, upper.upper);
    if (diff < 0)
        return true;
    if (diff > 0)
        return false;
    return lower.lowerInclusive && upper.upperInclusive;
}
function comparatorsOverlapTargetMajor(comparators, targetMajor) {
    const target = {
        lower: [targetMajor, 0, 0],
        lowerInclusive: true,
        upper: [targetMajor + 1, 0, 0],
        upperInclusive: false,
    };
    let interval = {
        lowerInclusive: true,
        upperInclusive: true,
    };
    for (const comparator of comparators) {
        if (!comparatorAllowsTargetMajor(comparator, target.lower, target.upper))
            return false;
        const bounds = boundsForComparator(comparator);
        if (!bounds)
            continue;
        const lower = laterLower(interval, bounds);
        const upper = earlierUpper(interval, bounds);
        interval = { ...lower, ...upper };
        if (!intervalsOverlap(interval, target))
            return false;
    }
    return intervalsOverlap(interval, target);
}
function expandToken(token) {
    const trimmed = token.trim();
    if (!trimmed || trimmed === '*' || /^[xX]$/.test(trimmed))
        return [];
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
    // Bare versions intentionally lock to semver-major compatibility, discarding minor/patch.
    if (/^v?\d+(?:\.\d+){0,2}$/.test(trimmed)) {
        const [major] = parseVersion(trimmed);
        return [`>=${major}.0.0`, `<${major + 1}.0.0`];
    }
    return [trimmed];
}
function isNodeEngineTargetCompatible(range, targetMajor) {
    if (!range || !range.trim())
        return undefined;
    const clauses = range.split('||').map((clause) => clause.trim()).filter(Boolean);
    if (clauses.length === 0)
        return undefined;
    return clauses.some((clause) => {
        const hyphen = clause.match(/^\s*v?(\d+(?:\.\d+){0,2})\s+-\s+v?(\d+(?:\.\d+){0,2})\s*$/);
        const tokens = hyphen ? [`>=${hyphen[1]}`, `<=${hyphen[2]}`] : clause.split(/\s+/);
        const comparators = tokens.flatMap(expandToken);
        return comparators.length === 0 || comparatorsOverlapTargetMajor(comparators, targetMajor);
    });
}
