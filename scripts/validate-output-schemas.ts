import https from 'https';
import Ajv from 'ajv';
import AjvDraft04 from 'ajv-draft-04';
import Ajv2020 from 'ajv/dist/2020';
import addFormats from 'ajv-formats';
import type { AggregatedData, DependencyRecord } from '../src/types';
import { renderCycloneDx, renderSarif, renderSpdx } from '../src/outputFormats';
import { REPORT_JSON_SCHEMA } from '../src/schema';

const CYCLONEDX_COMMIT = 'c320fc0f0b46873864927d9d5684eea7ba439728';
const SPDX_COMMIT = 'aadf3b0b8dbbabdb4d880b0fc714255fea436ff7';
const SARIF_COMMIT = 'ed71d4f62db866ce3698a08a5ec3f7f2e775545d';

const CYCLONEDX_SCHEMA = `https://raw.githubusercontent.com/CycloneDX/specification/${CYCLONEDX_COMMIT}/schema/bom-1.5.schema.json`;
const SPDX_SCHEMA = `https://raw.githubusercontent.com/spdx/spdx-spec/${SPDX_COMMIT}/schemas/spdx-schema.json`;
const SARIF_SCHEMA = `https://raw.githubusercontent.com/oasis-tcs/sarif-spec/${SARIF_COMMIT}/sarif-2.1/schema/sarif-schema-2.1.0.json`;

function fetchJson(url: string, redirects = 0): Promise<any> {
  return new Promise((resolve, reject) => {
    if (redirects > 4) {
      reject(new Error(`Too many redirects while fetching ${url}`));
      return;
    }
    const request = https.get(url, { headers: { 'user-agent': 'dependency-radar-schema-test' } }, (response) => {
      const status = response.statusCode || 0;
      if (status >= 300 && status < 400 && response.headers.location) {
        response.resume();
        fetchJson(new URL(response.headers.location, url).toString(), redirects + 1).then(resolve, reject);
        return;
      }
      if (status < 200 || status >= 300) {
        response.resume();
        reject(new Error(`Schema fetch failed (${status}): ${url}`));
        return;
      }
      const chunks: Buffer[] = [];
      let bytes = 0;
      response.on('data', (chunk) => {
        bytes += chunk.length;
        if (bytes > 2 * 1024 * 1024) {
          request.destroy(new Error(`Schema exceeds 2 MiB: ${url}`));
          return;
        }
        chunks.push(Buffer.from(chunk));
      });
      response.on('end', () => {
        try {
          resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')));
        } catch (error) {
          reject(error);
        }
      });
    });
    request.setTimeout(15_000, () => request.destroy(new Error(`Schema fetch timed out: ${url}`)));
    request.on('error', reject);
  });
}

function formatErrors(errors: unknown): string {
  return JSON.stringify(errors, null, 2);
}

async function validateDraft7(schemaUrl: string, value: unknown, schemaAliases: Record<string, string> = {}): Promise<void> {
  const ajv = new Ajv({ allErrors: true, strict: false, logger: false });
  addFormats(ajv);
  for (const [alias, url] of Object.entries(schemaAliases)) {
    ajv.addSchema(await fetchJson(url), alias);
  }
  const validate = ajv.compile(await fetchJson(schemaUrl));
  if (!validate(value)) throw new Error(`Schema validation failed for ${schemaUrl}:\n${formatErrors(validate.errors)}`);
}

async function validateDraft4(schemaUrl: string, value: unknown): Promise<void> {
  const ajv = new AjvDraft04({ allErrors: true, strict: false, logger: false });
  addFormats(ajv);
  const validate = ajv.compile(await fetchJson(schemaUrl));
  if (!validate(value)) throw new Error(`Schema validation failed for ${schemaUrl}:\n${formatErrors(validate.errors)}`);
}

function validateDependencyRadar(value: unknown): void {
  const ajv = new Ajv2020({ allErrors: true, strict: false, logger: false });
  addFormats(ajv);
  const validate = ajv.compile(REPORT_JSON_SCHEMA);
  if (!validate(value)) throw new Error(`Dependency Radar schema validation failed:\n${formatErrors(validate.errors)}`);
}

const dependency: DependencyRecord = {
  package: {
    id: 'example@1.0.0',
    name: 'example',
    version: '1.0.0',
    deprecated: false,
    links: {
      npm: 'https://registry.npmjs.org/example/-/example-1.0.0.tgz',
      repository: 'https://github.com/example/example'
    }
  },
  compliance: {
    license: {
      declared: { spdxId: 'MIT OR Apache-2.0', expression: true, deprecated: false, valid: true },
      status: 'declared-only'
    },
    licenseRisk: 'green'
  },
  security: {
    summary: { critical: 0, high: 0, moderate: 0, low: 0, highest: 'none', risk: 'green' }
  },
  upgrade: { nodeEngine: null },
  usage: {
    direct: true,
    scope: 'runtime',
    depth: 1,
    origins: { rootPackageCount: 1, topRootPackages: [{ name: 'example', version: '1.0.0' }], parentPackageCount: 0, topParentPackages: [] },
    tsTypes: 'none'
  },
  graph: {
    fanIn: 0,
    fanOut: 1,
    subDeps: {
      dep: { child: ['^2.0.0', 'child@2.0.0'] },
      peer: { child: ['^2.0.0', 'child@2.0.0'] }
    }
  },
  size: { unpackedBytes: 0, fileCount: 0 },
  maintenance: { attempted: true, ok: false, status: 'unknown' }
};

const child: DependencyRecord = {
  ...dependency,
  package: { ...dependency.package, id: 'child@2.0.0', name: 'child', version: '2.0.0' },
  compliance: {
    license: { declared: { spdxId: 'MIT', expression: false, deprecated: false, valid: true }, status: 'declared-only' },
    licenseRisk: 'green'
  },
  graph: { fanIn: 1, fanOut: 0, subDeps: {} }
};

const data = {
  schemaVersion: '1.6',
  generatedAt: '2026-01-01T00:00:00.000Z',
  dependencyRadarVersion: '0.0.0-test',
  git: { branch: 'test' },
  project: { projectDir: '/fixture', name: 'fixture', version: '1.0.0' },
  environment: { nodeVersion: '20.0.0', runtimeVersion: 'v20.0.0', minRequiredMajor: 14 },
  workspaces: { enabled: false },
  summary: { dependencyCount: 2, directCount: 1, transitiveCount: 1, findingCount: 1 },
  scanStatus: {
    complete: true,
    collectors: {
      dependencyTree: 'available',
      audit: 'available',
      imports: 'available',
      maintenance: 'available',
      registryMetadata: 'available',
      supplyChain: 'available'
    },
    warnings: []
  },
  findings: [{
    id: 'fixture-finding',
    category: 'security',
    severity: 'warning',
    title: 'Fixture finding',
    message: 'Fixture message',
    packageId: 'example@1.0.0',
    packageName: 'example',
    packageVersion: '1.0.0',
    recommendation: 'Review the fixture',
    evidence: 'fixture evidence'
  }],
  dependencies: { 'example@1.0.0': dependency, 'child@2.0.0': child }
} as AggregatedData;

async function main(): Promise<void> {
  const cycloneDx = JSON.parse(renderCycloneDx(data));
  const spdx = JSON.parse(renderSpdx(data));
  const sarif = JSON.parse(renderSarif(data));
  const cycloneBase = `https://raw.githubusercontent.com/CycloneDX/specification/${CYCLONEDX_COMMIT}/schema`;

  await validateDraft7(CYCLONEDX_SCHEMA, cycloneDx, {
    'http://cyclonedx.org/schema/spdx.schema.json': `${cycloneBase}/spdx.schema.json`,
    'http://cyclonedx.org/schema/jsf-0.82.schema.json': `${cycloneBase}/jsf-0.82.schema.json`,
  });
  await validateDraft7(SPDX_SCHEMA, spdx);
  await validateDraft4(SARIF_SCHEMA, sarif);
  validateDependencyRadar(data);
  console.log('✓ CycloneDX 1.5, SPDX 2.3, SARIF 2.1, and Dependency Radar outputs passed schema validation');
}

main().catch((error) => {
  console.error(error instanceof Error ? error.stack || error.message : String(error));
  process.exitCode = 1;
});
