"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.parseYamlLike = parseYamlLike;
exports.parseYarnV1Lockfile = parseYarnV1Lockfile;
exports.splitSelectorList = splitSelectorList;
/**
 * Parse a YAML-like string into a plain object supporting only the subset used by lockfiles.
 *
 * The function is tolerant of comments and indentation but intentionally limits supported YAML
 * features; on malformed input or when the top-level result is not a mapping, it returns an empty object.
 *
 * @returns A plain object representing the parsed mapping, or an empty object if parsing fails or no top-level mapping is present.
 */
function parseYamlLike(raw) {
    var _a;
    var _b;
    try {
        const lines = [];
        for (const rawLine of raw.split(/\r?\n/)) {
            const noComment = stripYamlInlineComment(rawLine).replace(/\s+$/, '');
            if (!noComment.trim())
                continue;
            const indent = (_b = (_a = noComment.match(/^(\s*)/)) === null || _a === void 0 ? void 0 : _a[1].length) !== null && _b !== void 0 ? _b : 0;
            lines.push({
                indent,
                content: noComment.trim()
            });
        }
        let index = 0;
        /**
         * Parse either a mapping or sequence node at the current cursor position.
         */
        const parseNode = (indentLevel) => {
            if (index >= lines.length)
                return undefined;
            if (lines[index].indent < indentLevel)
                return undefined;
            if (lines[index].indent === indentLevel && lines[index].content.startsWith('- ')) {
                return parseSequence(indentLevel);
            }
            return parseMapping(indentLevel);
        };
        /**
         * Parse an indentation-scoped YAML mapping.
         */
        const parseMapping = (indentLevel) => {
            const out = {};
            while (index < lines.length) {
                const line = lines[index];
                if (line.indent < indentLevel)
                    break;
                if (line.indent > indentLevel) {
                    index += 1;
                    continue;
                }
                if (line.content.startsWith('- '))
                    break;
                const colonIndex = findYamlMapSeparator(line.content);
                if (colonIndex <= 0) {
                    index += 1;
                    continue;
                }
                const key = unwrapOuterQuotes(line.content.slice(0, colonIndex));
                const valueToken = line.content.slice(colonIndex + 1).trim();
                index += 1;
                if (valueToken) {
                    out[key] = parseYamlScalar(valueToken);
                    continue;
                }
                if (index < lines.length && lines[index].indent > indentLevel) {
                    out[key] = parseNode(lines[index].indent);
                }
                else {
                    out[key] = null;
                }
            }
            return out;
        };
        /**
         * Parse an indentation-scoped YAML sequence.
         */
        const parseSequence = (indentLevel) => {
            const values = [];
            while (index < lines.length) {
                const line = lines[index];
                if (line.indent < indentLevel)
                    break;
                if (line.indent !== indentLevel || !line.content.startsWith('- '))
                    break;
                const valueToken = line.content.slice(2).trim();
                index += 1;
                if (valueToken) {
                    values.push(parseYamlScalar(valueToken));
                    if (index < lines.length && lines[index].indent > indentLevel) {
                        parseNode(lines[index].indent);
                    }
                    continue;
                }
                if (index < lines.length && lines[index].indent > indentLevel) {
                    values.push(parseNode(lines[index].indent));
                }
                else {
                    values.push(null);
                }
            }
            return values;
        };
        const parsed = parseNode(0);
        if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
            return {};
        }
        return parsed;
    }
    catch {
        return {};
    }
}
/**
 * Parses Yarn v1 lockfile content into selector-to-entry mappings.
 *
 * @param raw - The raw text content of a Yarn v1 lockfile
 * @returns A Map from selector string to `YarnLockEntry`, or `undefined` if no entries could be parsed
 */
function parseYarnV1Lockfile(raw) {
    var _a;
    var _b;
    try {
        const map = new Map();
        const lines = raw.split(/\r?\n/);
        let currentSelectors = [];
        let currentEntry;
        let currentSection;
        // Persist the currently parsed entry into every selector alias that points to it.
        const flushEntry = () => {
            if (!currentEntry || currentSelectors.length === 0)
                return;
            const entry = {};
            if (currentEntry.version)
                entry.version = currentEntry.version;
            if (currentEntry.dependencies && Object.keys(currentEntry.dependencies).length > 0) {
                entry.dependencies = { ...currentEntry.dependencies };
            }
            if (currentEntry.optionalDependencies && Object.keys(currentEntry.optionalDependencies).length > 0) {
                entry.optionalDependencies = { ...currentEntry.optionalDependencies };
            }
            for (const selector of currentSelectors) {
                if (!map.has(selector)) {
                    map.set(selector, entry);
                }
            }
        };
        for (const rawLine of lines) {
            const line = rawLine.replace(/\s+$/, '');
            const trimmed = line.trim();
            if (!trimmed || trimmed.startsWith('#'))
                continue;
            const indent = (_b = (_a = line.match(/^(\s*)/)) === null || _a === void 0 ? void 0 : _a[1].length) !== null && _b !== void 0 ? _b : 0;
            if (indent === 0 && trimmed.endsWith(':')) {
                flushEntry();
                currentSelectors = splitSelectorList(trimmed.slice(0, -1));
                currentEntry = {};
                currentSection = undefined;
                continue;
            }
            if (!currentEntry)
                continue;
            if (indent === 2) {
                if (trimmed === 'dependencies:') {
                    currentSection = 'dependencies';
                    continue;
                }
                if (trimmed === 'optionalDependencies:') {
                    currentSection = 'optionalDependencies';
                    continue;
                }
                currentSection = undefined;
                const pair = parseYarnTokenPair(trimmed);
                if (!pair)
                    continue;
                if (pair[0] === 'version' && pair[1]) {
                    currentEntry.version = pair[1];
                }
                continue;
            }
            if (indent >= 4 && currentSection) {
                const pair = parseYarnTokenPair(trimmed);
                if (!pair)
                    continue;
                const [name, spec] = pair;
                if (!name || !spec)
                    continue;
                if (currentSection === 'dependencies') {
                    if (!currentEntry.dependencies)
                        currentEntry.dependencies = {};
                    currentEntry.dependencies[name] = spec;
                }
                else {
                    if (!currentEntry.optionalDependencies)
                        currentEntry.optionalDependencies = {};
                    currentEntry.optionalDependencies[name] = spec;
                }
            }
        }
        flushEntry();
        return map.size > 0 ? map : undefined;
    }
    catch {
        return undefined;
    }
}
/**
 * Split a comma-separated selector list into individual selector strings, respecting quotes and escapes.
 *
 * Handles quoted tokens (single and double quotes), preserves escaped characters inside double-quoted tokens,
 * trims whitespace and unwraps optional outer quotes from each selector, and ignores empty tokens.
 *
 * @param selectorKey - The raw selector list (e.g. `"a@1", b@2`) to split and normalize
 * @returns An array of normalized selector strings in order of appearance
 */
function splitSelectorList(selectorKey) {
    const out = tokenizeSelectorParts(selectorKey.trim())
        .map(normalizeSelectorToken)
        .filter(Boolean);
    // Yarn Berry often stores the *entire* selector list as one quoted scalar.
    // If that happens, split the unwrapped scalar again to recover aliases.
    if (out.length === 1 && out[0].includes(',')) {
        return tokenizeSelectorParts(out[0])
            .map(normalizeSelectorToken)
            .filter(Boolean);
    }
    return out;
}
/**
 * Tokenize a selector list by commas that are outside quote scopes.
 *
 * @param value - Raw selector list text.
 * @returns Raw selector tokens in source order.
 */
function tokenizeSelectorParts(value) {
    const out = [];
    let current = '';
    let inSingle = false;
    let inDouble = false;
    let escaped = false;
    for (const ch of value) {
        if (inDouble && ch === '\\' && !escaped) {
            escaped = true;
            current += ch;
            continue;
        }
        if (ch === "'" && !inDouble) {
            inSingle = !inSingle;
            current += ch;
            escaped = false;
            continue;
        }
        if (ch === '"' && !inSingle && !escaped) {
            inDouble = !inDouble;
            current += ch;
            continue;
        }
        if (ch === ',' && !inSingle && !inDouble) {
            out.push(current);
            current = '';
            escaped = false;
            continue;
        }
        current += ch;
        escaped = false;
    }
    out.push(current);
    return out;
}
/**
 * Normalize a selector token by trimming surrounding whitespace and removing optional outer quotes.
 *
 * @param value - The selector token to normalize
 * @returns The normalized selector string without outer quotes
 */
function normalizeSelectorToken(value) {
    return unwrapOuterQuotes(value.trim());
}
/**
 * Parse a single Yarn v1 lockfile token pair from a line containing a name and a spec.
 *
 * @param value - The line to parse, containing a name token followed by a spec token; tokens may be quoted.
 * @returns A two-element tuple `[name, spec]` with outer quotes removed, or `undefined` if the line does not contain a valid pair.
 */
function parseYarnTokenPair(value) {
    const first = readQuotedOrBareToken(value, 0);
    if (!first)
        return undefined;
    const second = value.slice(first.next).trim();
    if (!second)
        return undefined;
    return [unwrapOuterQuotes(first.token.trim()), unwrapOuterQuotes(second)];
}
/**
 * Reads the next token from a string, supporting quoted (single or double) and bare tokens.
 *
 * @param value - The input string to read a token from.
 * @param start - The index at which to begin scanning; leading whitespace is skipped.
 * @returns An object `{ token, next }` where `token` is the raw token (quoted tokens include their surrounding quotes and any escape sequences) and `next` is the index immediately after the token, or `undefined` if no token is found or a quoted token is unterminated.
 */
function readQuotedOrBareToken(value, start) {
    let index = start;
    while (index < value.length && /\s/.test(value[index]))
        index += 1;
    if (index >= value.length)
        return undefined;
    const firstChar = value[index];
    if (firstChar === '"' || firstChar === "'") {
        const quote = firstChar;
        let token = quote;
        index += 1;
        let escaped = false;
        while (index < value.length) {
            const ch = value[index];
            token += ch;
            if (quote === '"' && ch === '\\' && !escaped) {
                escaped = true;
                index += 1;
                continue;
            }
            if (ch === quote && !escaped) {
                return { token, next: index + 1 };
            }
            escaped = false;
            index += 1;
        }
        return undefined;
    }
    let end = index;
    while (end < value.length && !/\s/.test(value[end]))
        end += 1;
    return { token: value.slice(index, end), next: end };
}
/**
 * Strip an inline YAML-style comment from a single line while preserving content inside quotes.
 *
 * @param rawLine - A single line of YAML-like text that may contain an inline `#` comment
 * @returns The substring up to (but not including) the first `#` character that is not inside single or double quotes; returns the original line if no such comment is found
 */
function stripYamlInlineComment(rawLine) {
    let inSingle = false;
    let inDouble = false;
    for (let i = 0; i < rawLine.length; i += 1) {
        const ch = rawLine[i];
        const prev = i > 0 ? rawLine[i - 1] : '';
        if (ch === "'" && !inDouble) {
            inSingle = !inSingle;
            continue;
        }
        if (ch === '"' && !inSingle && prev !== '\\') {
            inDouble = !inDouble;
            continue;
        }
        if (ch === '#' && !inSingle && !inDouble) {
            return rawLine.slice(0, i);
        }
    }
    return rawLine;
}
/**
 * Locate the colon that separates a YAML mapping key from its value, ignoring colons inside quoted strings.
 *
 * @returns The index of the separating colon in `content`, or `-1` if none is found. A colon is considered a separator only if it is not inside single-quoted or double-quoted strings (double quotes may use backslash to escape) and is followed by whitespace or the end of the line.
 */
function findYamlMapSeparator(content) {
    let inSingle = false;
    let inDouble = false;
    for (let i = 0; i < content.length; i += 1) {
        const ch = content[i];
        const prev = i > 0 ? content[i - 1] : '';
        if (ch === "'" && !inDouble) {
            inSingle = !inSingle;
            continue;
        }
        if (ch === '"' && !inSingle && prev !== '\\') {
            inDouble = !inDouble;
            continue;
        }
        if (ch !== ':' || inSingle || inDouble)
            continue;
        const next = content[i + 1];
        if (next === undefined || next === ' ' || next === '\t') {
            return i;
        }
    }
    return -1;
}
/**
 * Convert a YAML-like scalar token into its corresponding JavaScript value for the lockfile parser.
 *
 * @param value - The scalar token to parse (may be quoted or a special literal)
 * @returns The parsed value: `''` for empty input, `{}` for `'{}'`, `[]` for `'[]'`, `null` for `'null'` or `'~'`, `true` for `'true'`, `false` for `'false'`, or the unquoted string otherwise.
 */
function parseYamlScalar(value) {
    const normalized = value.trim();
    if (!normalized)
        return '';
    if (normalized === '{}')
        return {};
    if (normalized === '[]')
        return [];
    if (normalized === 'null' || normalized === '~')
        return null;
    if (normalized === 'true')
        return true;
    if (normalized === 'false')
        return false;
    return unwrapOuterQuotes(normalized);
}
/**
 * Remove matching outer single or double quotes from a string and unescape their common escape sequences.
 *
 * @param value - The input string that may be wrapped in matching quotes
 * @returns The trimmed string with outer matching quotes removed; for double-quoted input, unescapes `\"` to `"` and `\\` to `\`; for single-quoted input, collapses doubled single quotes `''` to `'`. If the input is not wrapped in matching quotes, returns the trimmed input unchanged.
 */
function unwrapOuterQuotes(value) {
    const trimmed = value.trim();
    if (trimmed.length < 2)
        return trimmed;
    const first = trimmed[0];
    const last = trimmed[trimmed.length - 1];
    if (first !== last || (first !== '"' && first !== "'")) {
        return trimmed;
    }
    const inner = trimmed.slice(1, -1);
    if (first === '"') {
        return inner
            .replace(/\\"/g, '"')
            .replace(/\\\\/g, '\\');
    }
    return inner.replace(/''/g, "'");
}
