import fs from 'fs/promises';
import path from 'path';
import https from 'https';

// Vendors the community module-replacements catalogue (an e18e project,
// https://e18e.dev) into src/generated/replacements.ts so replacement
// suggestions work fully offline at scan time.
//
// Deliberately pinned: updating the bundled replacement data is an explicit
// source change, not a network-dependent side effect of build or publish.
// Pin: es-tooling/module-replacements v3.0.0. Update the version and date
// alongside the commit when repinning.
const MODULE_REPLACEMENTS_COMMIT = '15f8e9d55e33ec0c5bef25396f8cb766ee8f56cb';
const MODULE_REPLACEMENTS_VERSION = 'v3.0.0';
const MODULE_REPLACEMENTS_DATE = '2026-07-03';
const MANIFESTS = ['native', 'micro-utilities', 'preferred'] as const;
const MANIFEST_BASE_URL =
  `https://raw.githubusercontent.com/es-tooling/module-replacements/${MODULE_REPLACEMENTS_COMMIT}/manifests`;

type ManifestName = (typeof MANIFESTS)[number];

type KnownUrl =
  | string
  | {
      type: 'mdn' | 'node' | 'e18e' | string;
      id: string;
    };

type ReplacementDescriptor = {
  id: string;
  type: 'native' | 'documented' | 'simple' | string;
  url?: KnownUrl;
  replacementModule?: string;
  description?: string;
};

type ModuleMapping = {
  type: string;
  moduleName: string;
  replacements: string[];
  url?: KnownUrl;
};

type Manifest = {
  replacements: Record<string, ReplacementDescriptor>;
  mappings: Record<string, ModuleMapping>;
};

async function fetchJson<T>(url: string): Promise<T> {
  return new Promise((resolve, reject) => {
    const req = https.get(url, (res) => {
      const status = res.statusCode || 0;
      if (status < 200 || status > 299) {
        clearTimeout(timeout);
        reject(new Error(`Failed to fetch ${url} (${status})`));
        res.resume();
        return;
      }
      const chunks: Buffer[] = [];
      res.on('data', (d) => chunks.push(Buffer.from(d)));
      res.on('end', () => {
        clearTimeout(timeout);
        try {
          const raw = Buffer.concat(chunks).toString('utf8');
          resolve(JSON.parse(raw) as T);
        } catch (err) {
          reject(err);
        }
      });
      res.on('error', (err) => {
        clearTimeout(timeout);
        reject(err);
      });
    });
    const timeout = setTimeout(() => {
      req.destroy(new Error(`Request timed out fetching ${url}`));
      reject(new Error(`Request timed out fetching ${url}`));
    }, 10_000);
    req.on('error', (err) => {
      clearTimeout(timeout);
      reject(err);
    });
  });
}

// Compact doc-URL form expanded at load by src/generated/replacements.ts.
// Mirrors resolveDocUrl in module-replacements src/util.ts, but keeps the
// well-known prefixes as one-letter codes so the generated file stays small.
function compactDocUrl(url?: KnownUrl): string | undefined {
  if (!url) return undefined;
  if (typeof url === 'string') return `u:${url}`;
  switch (url.type) {
    case 'mdn':
      return `m:${url.id}`;
    case 'node':
      return `n:${url.id}`;
    case 'e18e':
      return `e:${url.id}`;
    default:
      return undefined;
  }
}

type GeneratedEntry = {
  manifest: ManifestName;
  type: 'native' | 'documented' | 'simple';
  replacements: string[];
  docUrl?: string;
};

const MANIFEST_CODE: Record<ManifestName, string> = {
  native: 'n',
  'micro-utilities': 'm',
  preferred: 'p',
};
const TYPE_CODE: Record<'native' | 'documented' | 'simple', string> = {
  native: 'n',
  documented: 'd',
  simple: 's',
};

function normalizeDescriptorType(type: string): 'native' | 'documented' | 'simple' {
  if (type === 'native' || type === 'documented' || type === 'simple') return type;
  return 'documented';
}

function humanizeSnippetId(id: string): string {
  return id.replace(/^snippet::/, '').replace(/-/g, ' ');
}

function buildEntry(manifest: ManifestName, mapping: ModuleMapping, descriptors: Record<string, ReplacementDescriptor>): GeneratedEntry | undefined {
  const names: string[] = [];
  let entryType: 'native' | 'documented' | 'simple' | undefined;
  let docUrl = compactDocUrl(mapping.url);

  for (const replacementId of mapping.replacements || []) {
    const descriptor = descriptors[replacementId];
    if (!descriptor) {
      // Preferred-manifest replacement lists may reference plain module names
      // that have no descriptor of their own.
      names.push(replacementId);
      if (!entryType) entryType = 'documented';
      continue;
    }
    const type = normalizeDescriptorType(descriptor.type);
    if (!entryType) entryType = type;
    if (type === 'simple') {
      names.push(`inline snippet (${humanizeSnippetId(descriptor.id)})`);
    } else if (type === 'documented' && descriptor.replacementModule) {
      names.push(descriptor.replacementModule);
    } else {
      names.push(descriptor.id);
    }
    if (!docUrl) docUrl = compactDocUrl(descriptor.url);
  }

  if (names.length === 0 || !entryType) return undefined;
  return {
    manifest,
    type: entryType,
    replacements: Array.from(new Set(names)),
    ...(docUrl ? { docUrl } : {})
  };
}

async function main(): Promise<void> {
  const manifests = await Promise.all(
    MANIFESTS.map((name) => fetchJson<Manifest>(`${MANIFEST_BASE_URL}/${name}.json`))
  );

  // Manifest order doubles as priority: a module listed in both native and
  // preferred keeps its native suggestion (the stronger claim).
  const entries = new Map<string, GeneratedEntry>();
  manifests.forEach((manifest, index) => {
    const manifestName = MANIFESTS[index];
    for (const mapping of Object.values(manifest.mappings || {})) {
      if (!mapping?.moduleName || entries.has(mapping.moduleName)) continue;
      const entry = buildEntry(manifestName, mapping, manifest.replacements || {});
      if (entry) entries.set(mapping.moduleName, entry);
    }
  });

  const sortedNames = Array.from(entries.keys()).sort((a, b) => a.localeCompare(b));
  const lines = sortedNames.map((name) => {
    const entry = entries.get(name) as GeneratedEntry;
    const row: unknown[] = [
      name,
      MANIFEST_CODE[entry.manifest],
      TYPE_CODE[entry.type],
      entry.docUrl ?? '',
      ...entry.replacements,
    ];
    return `  ${JSON.stringify(row)}`;
  });

  const filePath = path.join(__dirname, '..', 'src', 'generated', 'replacements.ts');
  const content = `// AUTO-GENERATED FILE - DO NOT EDIT DIRECTLY
// Generated by scripts/build-replacements.ts
// Source: es-tooling/module-replacements (an e18e project, https://e18e.dev)
// Commit: ${MODULE_REPLACEMENTS_COMMIT} (${MODULE_REPLACEMENTS_VERSION}, ${MODULE_REPLACEMENTS_DATE})
// Licence: MIT (https://github.com/es-tooling/module-replacements/blob/main/LICENSE)

export type ReplacementManifestName = 'native' | 'micro-utilities' | 'preferred';

export interface ModuleReplacementEntry {
  manifest: ReplacementManifestName;
  type: 'native' | 'documented' | 'simple';
  replacements: string[];
  docUrl?: string;
}

export const MODULE_REPLACEMENTS_PROJECT_URL = 'https://github.com/es-tooling/module-replacements';
export const E18E_PROJECT_URL = 'https://e18e.dev';
export const MODULE_REPLACEMENTS_VERSION = '${MODULE_REPLACEMENTS_VERSION}';
export const MODULE_REPLACEMENTS_DATE = '${MODULE_REPLACEMENTS_DATE}';

// One row per module: [name, manifest, type, docUrl, ...replacements].
// Single-letter codes keep the vendored catalogue compact while staying
// plain, readable data — no encoding or compression involved:
//   manifest: n = native, m = micro-utilities, p = preferred
//   type:     n = native, d = documented, s = simple
//   docUrl:   'e:<id>' -> https://e18e.dev/docs/replacements/<id>
//             'm:<id>' -> https://developer.mozilla.org/en-US/docs/<id>
//             'n:<id>' -> https://nodejs.org/<id>
//             'u:<url>' -> the URL verbatim; '' -> no doc link
type CompactRow = [string, string, string, string, ...string[]];

const ROWS: CompactRow[] = [
${lines.join(',\n')}
];

const MANIFEST_BY_CODE: Record<string, ReplacementManifestName> = {
  n: 'native',
  m: 'micro-utilities',
  p: 'preferred',
};
const TYPE_BY_CODE: Record<string, ModuleReplacementEntry['type']> = {
  n: 'native',
  d: 'documented',
  s: 'simple',
};

function expandDocUrl(compact: string): string | undefined {
  if (!compact) return undefined;
  const id = compact.slice(2);
  switch (compact[0]) {
    case 'e':
      return 'https://e18e.dev/docs/replacements/' + id;
    case 'm':
      return 'https://developer.mozilla.org/en-US/docs/' + id;
    case 'n':
      return 'https://nodejs.org/' + id;
    default:
      return id;
  }
}

export const MODULE_REPLACEMENTS: Record<string, ModuleReplacementEntry> = {};
for (const [name, manifest, type, docUrl, ...replacements] of ROWS) {
  const expanded = expandDocUrl(docUrl);
  MODULE_REPLACEMENTS[name] = {
    manifest: MANIFEST_BY_CODE[manifest] ?? 'preferred',
    type: TYPE_BY_CODE[type] ?? 'documented',
    replacements,
    ...(expanded ? { docUrl: expanded } : {}),
  };
}
`;
  await fs.mkdir(path.dirname(filePath), { recursive: true });
  await fs.writeFile(filePath, content, 'utf8');
  console.log(`Wrote ${Number(entries.size)} module replacement entries to src/generated/replacements.ts`);
}

main().catch((err) => {
  // Error text can embed fetched-response fragments; strip line breaks so a
  // hostile payload cannot forge extra log lines (CodeQL js/log-injection).
  const message = err instanceof Error ? err.message : String(err);
  console.error(message.replace(/\n/g, '').replace(/\r/g, ''));
  process.exit(1);
});
