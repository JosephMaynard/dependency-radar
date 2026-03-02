export type YarnLockEntry = {
  version?: string;
  dependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
};

type ParsedYamlLine = {
  indent: number;
  content: string;
};

/**
 * Parse a YAML-like string into a plain object.
 *
 * The parser intentionally supports only the subset used by lockfiles and
 * returns an empty object on malformed input.
 */
export function parseYamlLike(raw: string): Record<string, unknown> {
  try {
    const lines: ParsedYamlLine[] = [];
    for (const rawLine of raw.split(/\r?\n/)) {
      const noComment = stripYamlInlineComment(rawLine).replace(/\s+$/, '');
      if (!noComment.trim()) continue;
      const indent = noComment.match(/^(\s*)/)?.[1].length ?? 0;
      lines.push({
        indent,
        content: noComment.trim()
      });
    }

    let index = 0;

    /**
     * Parse either a mapping or sequence node at the current cursor position.
     */
    const parseNode = (indentLevel: number): unknown => {
      if (index >= lines.length) return undefined;
      if (lines[index].indent < indentLevel) return undefined;
      if (lines[index].indent === indentLevel && lines[index].content.startsWith('- ')) {
        return parseSequence(indentLevel);
      }
      return parseMapping(indentLevel);
    };

    /**
     * Parse an indentation-scoped YAML mapping.
     */
    const parseMapping = (indentLevel: number): Record<string, unknown> => {
      const out: Record<string, unknown> = {};
      while (index < lines.length) {
        const line = lines[index];
        if (line.indent < indentLevel) break;
        if (line.indent > indentLevel) {
          index += 1;
          continue;
        }
        if (line.content.startsWith('- ')) break;
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
        } else {
          out[key] = null;
        }
      }
      return out;
    };

    /**
     * Parse an indentation-scoped YAML sequence.
     */
    const parseSequence = (indentLevel: number): unknown[] => {
      const values: unknown[] = [];
      while (index < lines.length) {
        const line = lines[index];
        if (line.indent < indentLevel) break;
        if (line.indent !== indentLevel || !line.content.startsWith('- ')) break;
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
        } else {
          values.push(null);
        }
      }
      return values;
    };

    const parsed = parseNode(0);
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      return {};
    }
    return parsed as Record<string, unknown>;
  } catch {
    return {};
  }
}

/**
 * Parse Yarn v1 lockfile content into lock entries.
 *
 * Returns `undefined` when no entries can be parsed.
 */
export function parseYarnV1Lockfile(raw: string): Map<string, YarnLockEntry> | undefined {
  try {
    const map = new Map<string, YarnLockEntry>();
    const lines = raw.split(/\r?\n/);

    let currentSelectors: string[] = [];
    let currentEntry: YarnLockEntry | undefined;
    let currentSection: 'dependencies' | 'optionalDependencies' | undefined;

    // Persist the currently parsed entry into every selector alias that points to it.
    const flushEntry = () => {
      if (!currentEntry || currentSelectors.length === 0) return;
      const entry: YarnLockEntry = {};
      if (currentEntry.version) entry.version = currentEntry.version;
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
      if (!trimmed || trimmed.startsWith('#')) continue;

      const indent = line.match(/^(\s*)/)?.[1].length ?? 0;
      if (indent === 0 && trimmed.endsWith(':')) {
        flushEntry();
        currentSelectors = splitSelectorList(trimmed.slice(0, -1));
        currentEntry = {};
        currentSection = undefined;
        continue;
      }

      if (!currentEntry) continue;

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
        if (!pair) continue;
        if (pair[0] === 'version' && pair[1]) {
          currentEntry.version = pair[1];
        }
        continue;
      }

      if (indent >= 4 && currentSection) {
        const pair = parseYarnTokenPair(trimmed);
        if (!pair) continue;
        const [name, spec] = pair;
        if (!name || !spec) continue;
        if (currentSection === 'dependencies') {
          if (!currentEntry.dependencies) currentEntry.dependencies = {};
          currentEntry.dependencies[name] = spec;
        } else {
          if (!currentEntry.optionalDependencies) currentEntry.optionalDependencies = {};
          currentEntry.optionalDependencies[name] = spec;
        }
      }
    }

    flushEntry();
    return map.size > 0 ? map : undefined;
  } catch {
    return undefined;
  }
}

/**
 * Split a selector list like `"a@1", b@2` into individual selectors.
 */
export function splitSelectorList(selectorKey: string): string[] {
  const normalized = unwrapOuterQuotes(selectorKey.trim());
  const out: string[] = [];
  let current = '';
  let inSingle = false;
  let inDouble = false;
  let escaped = false;

  for (const ch of normalized) {
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
      const selector = normalizeSelectorToken(current);
      if (selector) out.push(selector);
      current = '';
      escaped = false;
      continue;
    }
    current += ch;
    escaped = false;
  }

  const tail = normalizeSelectorToken(current);
  if (tail) out.push(tail);
  return out;
}

/**
 * Normalize one selector token by trimming and removing optional outer quotes.
 */
function normalizeSelectorToken(value: string): string {
  return unwrapOuterQuotes(value.trim());
}

/**
 * Parse a Yarn lockfile key/value line (`name "range"` style) into tuple form.
 */
function parseYarnTokenPair(value: string): [string, string] | undefined {
  const first = readQuotedOrBareToken(value, 0);
  if (!first) return undefined;
  const second = value.slice(first.next).trim();
  if (!second) return undefined;
  return [unwrapOuterQuotes(first.token.trim()), unwrapOuterQuotes(second)];
}

/**
 * Read one token from a string, supporting bare and quoted forms.
 */
function readQuotedOrBareToken(
  value: string,
  start: number
): { token: string; next: number } | undefined {
  let index = start;
  while (index < value.length && /\s/.test(value[index])) index += 1;
  if (index >= value.length) return undefined;

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
  while (end < value.length && !/\s/.test(value[end])) end += 1;
  return { token: value.slice(index, end), next: end };
}

/**
 * Remove inline YAML comments while respecting quoted strings.
 */
function stripYamlInlineComment(rawLine: string): string {
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
 * Find the mapping `:` separator in a YAML line while ignoring quoted colons.
 */
function findYamlMapSeparator(content: string): number {
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
    if (ch !== ':' || inSingle || inDouble) continue;
    const next = content[i + 1];
    if (next === undefined || next === ' ' || next === '\t') {
      return i;
    }
  }
  return -1;
}

/**
 * Parse a scalar token for the limited YAML subset needed by lockfiles.
 */
function parseYamlScalar(value: string): unknown {
  const normalized = value.trim();
  if (!normalized) return '';
  if (normalized === '{}') return {};
  if (normalized === '[]') return [];
  if (normalized === 'null' || normalized === '~') return null;
  if (normalized === 'true') return true;
  if (normalized === 'false') return false;
  return unwrapOuterQuotes(normalized);
}

/**
 * Remove matching outer quote characters and unescape common quote forms.
 */
function unwrapOuterQuotes(value: string): string {
  const trimmed = value.trim();
  if (trimmed.length < 2) return trimmed;
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
