"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.workspacePatternToRegex = workspacePatternToRegex;
exports.splitWorkspacePatterns = splitWorkspacePatterns;
exports.matchesWorkspacePatterns = matchesWorkspacePatterns;
exports.expandWorkspacePatterns = expandWorkspacePatterns;
exports.readWorkspacePatterns = readWorkspacePatterns;
exports.parsePlainVersion = parsePlainVersion;
exports.rangeSatisfies = rangeSatisfies;
const promises_1 = __importDefault(require("fs/promises"));
const path_1 = __importDefault(require("path"));
// Shared workspace-pattern matching for package.json#workspaces and
// pnpm-workspace.yaml globs. Supports the forms those files actually use:
// literal segments, `*` (one segment), `**` (any depth), and `!`-negated
// exclusion patterns. Kept dependency-free like the rest of the CLI.
function normalizePattern(pattern) {
    const segments = pattern
        .trim()
        .replace(/^[.][/\\]/, '')
        .replace(/[/\\]+$/, '')
        .split(/[/\\]+/g)
        .filter(Boolean);
    // Consecutive `**` segments are equivalent to one, and compiling them
    // separately produces adjacent identical star groups that backtrack
    // exponentially on non-matching input (patterns come from the scanned
    // project's manifest, which is untrusted).
    const collapsed = segments.filter((segment, index) => segment !== '**' || segments[index - 1] !== '**');
    return collapsed.join('/');
}
/** Convert one workspace glob into a full-match regex over a relative path. */
function workspacePatternToRegex(pattern) {
    const segments = normalizePattern(pattern).split('/');
    let body = '^';
    segments.forEach((segment, index) => {
        const isLast = index === segments.length - 1;
        if (segment === '**') {
            // Trailing `**` requires at least one segment below; mid-pattern `**`
            // spans zero or more whole segments (the next literal supplies its own
            // position after the optional group).
            body += isLast ? '.+' : '(?:[^/]+/)*';
            return;
        }
        const literal = segment
            .split('*')
            .map((piece) => piece.replace(/[.+^${}()|[\]\\?]/g, '\\$&'))
            .join('[^/]*');
        body += literal + (isLast ? '' : '/');
    });
    return new RegExp(`${body}$`);
}
function splitWorkspacePatterns(patterns) {
    const includes = [];
    const excludes = [];
    for (const raw of patterns) {
        const trimmed = raw.trim();
        if (!trimmed)
            continue;
        if (trimmed.startsWith('!'))
            excludes.push(trimmed.slice(1));
        else
            includes.push(trimmed);
    }
    return { includes, excludes };
}
/** True when relPath (posix separators) is selected by the pattern list. */
function matchesWorkspacePatterns(patterns, relPath) {
    const normalized = normalizePattern(relPath);
    if (!normalized || normalized.startsWith('..'))
        return false;
    const { includes, excludes } = splitWorkspacePatterns(patterns);
    if (!includes.some((p) => workspacePatternToRegex(p).test(normalized)))
        return false;
    return !excludes.some((p) => workspacePatternToRegex(p).test(normalized));
}
// Symlinked directories report isDirectory() === false from readdir, so the
// walk cannot cycle; the cap is only a backstop against pathological trees
// and sits far above real workspace layouts.
const WALK_MAX_DEPTH = 32;
async function listDirs(parent) {
    const entries = await promises_1.default.readdir(parent, { withFileTypes: true }).catch(() => []);
    return entries
        .filter((entry) => entry.isDirectory())
        .map((entry) => entry.name)
        .filter((name) => name !== 'node_modules' && !name.startsWith('.'));
}
/**
 * Expand a workspace pattern list to matching directories under rootDir.
 * Walks the tree (bounded depth, skipping node_modules and dotfiles) and
 * applies inclusion and `!` exclusion patterns over relative paths, so nested
 * globs like `packages/*&#47;plugins/*` and negations both work.
 */
async function expandWorkspacePatterns(rootDir, patterns) {
    const { includes, excludes } = splitWorkspacePatterns(patterns);
    if (includes.length === 0)
        return [];
    const includeRegexes = includes.map(workspacePatternToRegex);
    const excludeRegexes = excludes.map(workspacePatternToRegex);
    // Literal (glob-free) patterns can match directories the walk skips only
    // when explicitly listed (e.g. hidden dirs); resolve them directly too.
    const out = new Set();
    for (const literal of includes.filter((p) => !p.includes('*'))) {
        const rel = normalizePattern(literal);
        if (!rel || rel.startsWith('..'))
            continue;
        if (excludeRegexes.some((re) => re.test(rel)))
            continue;
        const abs = path_1.default.resolve(rootDir, rel);
        try {
            const stat = await promises_1.default.stat(abs);
            if (stat.isDirectory())
                out.add(abs);
        }
        catch {
            // Pattern points nowhere — ignore.
        }
    }
    const maxSegments = Math.min(WALK_MAX_DEPTH, Math.max(...includes.map((p) => {
        const segs = normalizePattern(p).split('/');
        return segs.includes('**') ? WALK_MAX_DEPTH : segs.length;
    }), 1));
    const walk = async (dir, relSegments) => {
        if (relSegments.length >= maxSegments)
            return;
        for (const name of await listDirs(dir)) {
            const childRel = [...relSegments, name];
            const relPath = childRel.join('/');
            const matchesInclude = includeRegexes.some((re) => re.test(relPath));
            const matchesExclude = excludeRegexes.some((re) => re.test(relPath));
            if (matchesInclude && !matchesExclude) {
                out.add(path_1.default.join(dir, name));
            }
            await walk(path_1.default.join(dir, name), childRel);
        }
    };
    await walk(rootDir, []);
    return Array.from(out).sort();
}
/**
 * Read a directory's workspace patterns: package.json#workspaces (array or
 * `{packages: []}` form) plus pnpm-workspace.yaml `packages:` entries.
 * Returns undefined when the directory declares no workspace configuration.
 */
async function readWorkspacePatterns(dir) {
    const patterns = [];
    let declared = false;
    try {
        const raw = await promises_1.default.readFile(path_1.default.join(dir, 'package.json'), 'utf8');
        const pkg = JSON.parse(raw);
        const ws = pkg === null || pkg === void 0 ? void 0 : pkg.workspaces;
        if (ws) {
            declared = true;
            if (Array.isArray(ws))
                patterns.push(...ws.filter((p) => typeof p === 'string'));
            else if (typeof ws === 'object' &&
                Array.isArray(ws.packages)) {
                patterns.push(...(ws.packages.filter((p) => typeof p === 'string')));
            }
        }
    }
    catch {
        // No package.json or unparsable — fall through to pnpm-workspace.yaml.
    }
    try {
        const raw = await promises_1.default.readFile(path_1.default.join(dir, 'pnpm-workspace.yaml'), 'utf8');
        declared = true;
        let inPackages = false;
        for (const line of raw.split(/\r?\n/)) {
            if (/^packages\s*:/.test(line)) {
                inPackages = true;
                continue;
            }
            if (inPackages) {
                const item = line.match(/^\s+-\s*(["']?)(.*?)\1\s*$/);
                if (item)
                    patterns.push(item[2]);
                else if (/^\S/.test(line))
                    inPackages = false;
            }
        }
    }
    catch {
        // No pnpm workspace file.
    }
    return declared ? patterns : undefined;
}
function parsePlainVersion(version) {
    const match = version.trim().match(/^v?(\d+)\.(\d+)\.(\d+)$/);
    if (!match)
        return undefined;
    return [Number(match[1]), Number(match[2]), Number(match[3])];
}
function compareTriples(a, b) {
    for (let i = 0; i < 3; i += 1) {
        if (a[i] !== b[i])
            return a[i] - b[i];
    }
    return 0;
}
const RANGE_TOKEN = /^(>=|<=|>|<|=|\^|~)?v?(\d+)(?:\.(\d+|[xX*]))?(?:\.(\d+|[xX*]))?$/;
function tokenSatisfies(token, v) {
    const match = token.match(RANGE_TOKEN);
    if (!match)
        return undefined;
    const op = match[1] || '';
    const major = Number(match[2]);
    const wild = (part) => part === undefined || part === 'x' || part === 'X' || part === '*';
    const minor = wild(match[3]) ? undefined : Number(match[3]);
    const patch = wild(match[4]) ? undefined : Number(match[4]);
    const lower = [major, minor !== null && minor !== void 0 ? minor : 0, patch !== null && patch !== void 0 ? patch : 0];
    switch (op) {
        case '>=':
            return compareTriples(v, lower) >= 0;
        case '>': {
            // >1.2 means at least 1.3.0; >1 means at least 2.0.0.
            const upper = patch !== undefined
                ? lower
                : minor !== undefined
                    ? [major, minor + 1, 0]
                    : [major + 1, 0, 0];
            return patch !== undefined
                ? compareTriples(v, lower) > 0
                : compareTriples(v, upper) >= 0;
        }
        case '<':
            return compareTriples(v, lower) < 0;
        case '<=': {
            // <=1.2 permits anything below 1.3.0; <=1 anything below 2.0.0.
            if (patch !== undefined)
                return compareTriples(v, lower) <= 0;
            const upper = minor !== undefined ? [major, minor + 1, 0] : [major + 1, 0, 0];
            return compareTriples(v, upper) < 0;
        }
        case '^': {
            if (compareTriples(v, lower) < 0)
                return false;
            if (major > 0)
                return v[0] === major;
            // ^0 / ^0.x accept any 0.y.z; ^0.y pins the minor; ^0.0.z pins patch.
            if (minor === undefined)
                return v[0] === 0;
            if (minor > 0 || patch === undefined)
                return v[0] === 0 && v[1] === minor;
            return v[0] === 0 && v[1] === 0 && v[2] === patch;
        }
        case '~': {
            if (compareTriples(v, lower) < 0)
                return false;
            if (minor === undefined)
                return v[0] === major;
            return v[0] === major && v[1] === minor;
        }
        default: {
            if (minor === undefined)
                return v[0] === major;
            if (patch === undefined)
                return v[0] === major && v[1] === minor;
            return compareTriples(v, lower) === 0;
        }
    }
}
/**
 * True/false when satisfaction of `spec` by `version` is decidable within
 * the supported grammar; undefined otherwise.
 */
function rangeSatisfies(spec, version) {
    const v = parsePlainVersion(version);
    if (!v)
        return undefined;
    const trimmed = spec.trim();
    if (!trimmed || trimmed === '*' || trimmed === 'x' || trimmed === 'X')
        return true;
    for (const union of trimmed.split('||')) {
        const part = union.trim();
        if (!part)
            return undefined;
        // Hyphen range: "1.2.3 - 2.0.0" is inclusive on both ends.
        const hyphen = part.match(/^(\S+)\s+-\s+(\S+)$/);
        const tokens = hyphen ? [`>=${hyphen[1]}`, `<=${hyphen[2]}`] : part.split(/\s+/);
        let all = true;
        for (const token of tokens) {
            const verdict = tokenSatisfies(token, v);
            if (verdict === undefined) {
                all = undefined;
                break;
            }
            if (!verdict)
                all = false;
        }
        if (all === undefined)
            return undefined;
        if (all)
            return true;
    }
    return false;
}
