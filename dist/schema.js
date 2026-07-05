"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.REPORT_JSON_SCHEMA = exports.COMPATIBLE_BASELINE_SCHEMA_VERSIONS = exports.REPORT_SCHEMA_VERSION = void 0;
exports.renderReportJsonSchema = renderReportJsonSchema;
exports.REPORT_SCHEMA_VERSION = '1.5';
// Baseline reports accepted by `compare`. Schema changes since 1.2 have been
// purely additive, and every consumer of baseline data optional-chains the
// newer fields, so older baselines remain valid comparison inputs.
exports.COMPATIBLE_BASELINE_SCHEMA_VERSIONS = ['1.2', '1.3', '1.4', exports.REPORT_SCHEMA_VERSION];
exports.REPORT_JSON_SCHEMA = {
    $schema: 'https://json-schema.org/draft/2020-12/schema',
    $id: 'https://dependency-radar.com/schemas/dependency-radar-1.5.schema.json',
    title: 'Dependency Radar Report',
    type: 'object',
    required: ['schemaVersion', 'generatedAt', 'dependencyRadarVersion', 'project', 'environment', 'workspaces', 'summary', 'dependencies'],
    properties: {
        schemaVersion: { const: exports.REPORT_SCHEMA_VERSION },
        generatedAt: { type: 'string', format: 'date-time' },
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
            required: ['signals'],
            properties: {
                signals: {
                    type: 'array',
                    items: {
                        type: 'object',
                        required: ['type', 'source', 'detail'],
                        properties: {
                            type: {
                                enum: [
                                    'git-dependency',
                                    'file-dependency',
                                    'non-registry-tarball',
                                    'missing-integrity',
                                    'unexpected-registry-host'
                                ]
                            },
                            packageName: { type: 'string' },
                            packageVersion: { type: 'string' },
                            packageId: { type: 'string' },
                            source: { type: 'string' },
                            detail: { type: 'string' }
                        },
                        additionalProperties: false
                    }
                },
                signatureAudit: {
                    type: 'object',
                    required: ['attempted', 'ok'],
                    properties: {
                        attempted: { type: 'boolean' },
                        ok: { type: 'boolean' },
                        status: { enum: ['verified', 'failed', 'skipped'] },
                        output: { type: 'string' },
                        error: { type: 'string' }
                    },
                    additionalProperties: false
                }
            },
            additionalProperties: false
        },
        findings: {
            type: 'array',
            items: {
                type: 'object',
                required: ['id', 'category', 'severity', 'packageId', 'packageName', 'packageVersion', 'title', 'message'],
                properties: {
                    id: { type: 'string' },
                    category: { enum: ['security', 'license', 'execution', 'upgrade', 'supply-chain'] },
                    severity: { enum: ['info', 'warning', 'error'] },
                    packageId: { type: 'string' },
                    packageName: { type: 'string' },
                    packageVersion: { type: 'string' },
                    title: { type: 'string' },
                    message: { type: 'string' },
                    evidence: { type: 'string' },
                    recommendation: { type: 'string' }
                },
                additionalProperties: false
            }
        },
        dependencies: {
            type: 'object',
            additionalProperties: { type: 'object', additionalProperties: true }
        }
    },
    additionalProperties: true
};
function renderReportJsonSchema() {
    return JSON.stringify(exports.REPORT_JSON_SCHEMA, null, 2);
}
