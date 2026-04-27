export const REPORT_SCHEMA_VERSION = '1.4';

export const REPORT_JSON_SCHEMA = {
  $schema: 'https://json-schema.org/draft/2020-12/schema',
  $id: 'https://dependency-radar.com/schemas/dependency-radar-1.4.schema.json',
  title: 'Dependency Radar Report',
  type: 'object',
  required: ['schemaVersion', 'generatedAt', 'dependencyRadarVersion', 'project', 'environment', 'workspaces', 'summary', 'dependencies'],
  properties: {
    schemaVersion: { const: REPORT_SCHEMA_VERSION },
    generatedAt: { type: 'string' },
    dependencyRadarVersion: { type: 'string' },
    git: {
      type: 'object',
      properties: { branch: { type: 'string' } },
      additionalProperties: true
    },
    project: { type: 'object', additionalProperties: true },
    environment: { type: 'object', additionalProperties: true },
    workspaces: { type: 'object', additionalProperties: true },
    summary: {
      type: 'object',
      required: ['dependencyCount', 'directCount', 'transitiveCount'],
      properties: {
        dependencyCount: { type: 'number' },
        directCount: { type: 'number' },
        transitiveCount: { type: 'number' },
        findingCount: { type: 'number' }
      },
      additionalProperties: true
    },
    supplyChain: {
      type: 'object',
      properties: {
        signals: { type: 'array', items: { type: 'object', additionalProperties: true } },
        signatureAudit: { type: 'object', additionalProperties: true }
      },
      additionalProperties: true
    },
    findings: { type: 'array', items: { type: 'object', additionalProperties: true } },
    dependencies: {
      type: 'object',
      additionalProperties: { type: 'object', additionalProperties: true }
    }
  },
  additionalProperties: true
};

export function renderReportJsonSchema(): string {
  return JSON.stringify(REPORT_JSON_SCHEMA, null, 2);
}

