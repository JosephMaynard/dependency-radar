"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.renderSarif = renderSarif;
exports.renderCycloneDx = renderCycloneDx;
exports.renderSpdx = renderSpdx;
exports.defaultOutputName = defaultOutputName;
const crypto_1 = require("crypto");
function purl(dep) {
    const encodedName = dep.package.name.startsWith('@')
        ? `%40${dep.package.name
            .slice(1)
            .split('/')
            .map(encodeURIComponent)
            .join('/')}`
        : encodeURIComponent(dep.package.name);
    return `pkg:npm/${encodedName}@${encodeURIComponent(dep.package.version)}`;
}
function safeExternalUrl(value) {
    if (!value)
        return undefined;
    try {
        const parsed = new URL(value);
        if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:')
            return undefined;
        parsed.username = '';
        parsed.password = '';
        return parsed.toString();
    }
    catch {
        return undefined;
    }
}
function findingLevel(finding) {
    if (finding.severity === 'error')
        return 'error';
    if (finding.severity === 'warning')
        return 'warning';
    return 'note';
}
function renderSarif(data) {
    const findings = data.findings || [];
    const rules = new Map();
    for (const finding of findings) {
        if (rules.has(finding.category))
            continue;
        rules.set(finding.category, {
            id: finding.category,
            name: finding.category,
            shortDescription: { text: `Dependency Radar ${finding.category} finding` },
            helpUri: 'https://github.com/JosephMaynard/dependency-radar'
        });
    }
    return JSON.stringify({
        version: '2.1.0',
        $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
        runs: [
            {
                tool: {
                    driver: {
                        name: 'Dependency Radar',
                        informationUri: 'https://github.com/JosephMaynard/dependency-radar',
                        semanticVersion: data.dependencyRadarVersion,
                        rules: Array.from(rules.values())
                    }
                },
                results: findings.map((finding) => ({
                    ruleId: finding.category,
                    level: findingLevel(finding),
                    message: { text: `${finding.title}: ${finding.message}` },
                    properties: {
                        dependencyRadarFindingId: finding.id,
                        packageId: finding.packageId,
                        packageName: finding.packageName,
                        packageVersion: finding.packageVersion,
                        recommendation: finding.recommendation,
                        evidence: finding.evidence
                    },
                    locations: [sarifLocation(finding)]
                }))
            }
        ]
    }, null, 2);
}
function sarifLocation(finding) {
    const extra = finding;
    return {
        physicalLocation: {
            artifactLocation: { uri: extra.sourceFile || extra.sourcePath || 'package.json' },
            region: { startLine: extra.startLine || 1 }
        }
    };
}
function licenseIds(dep) {
    const declared = dep.compliance.license.declared;
    const inferred = dep.compliance.license.inferred;
    if ((declared === null || declared === void 0 ? void 0 : declared.valid) && declared.spdxId) {
        return declared.expression
            ? [{ expression: declared.spdxId }]
            : [{ license: { id: declared.spdxId } }];
    }
    if (inferred === null || inferred === void 0 ? void 0 : inferred.spdxId)
        return [{ license: { id: inferred.spdxId } }];
    return [{ license: { name: 'UNKNOWN' } }];
}
function renderCycloneDx(data) {
    const dependencies = Object.values(data.dependencies || {});
    return JSON.stringify({
        bomFormat: 'CycloneDX',
        specVersion: '1.5',
        version: 1,
        metadata: {
            timestamp: data.generatedAt,
            tools: [{ vendor: 'Dependency Radar', name: 'dependency-radar', version: data.dependencyRadarVersion }],
            component: {
                type: 'application',
                name: data.project.name || data.project.projectDir,
                version: data.project.version || '0.0.0'
            }
        },
        components: dependencies.map((dep) => ({
            type: 'library',
            'bom-ref': dep.package.id,
            name: dep.package.name,
            version: dep.package.version,
            purl: purl(dep),
            licenses: licenseIds(dep),
            externalReferences: [
                safeExternalUrl(dep.package.links.npm) ? { type: 'distribution', url: safeExternalUrl(dep.package.links.npm) } : undefined,
                safeExternalUrl(dep.package.links.repository) ? { type: 'vcs', url: safeExternalUrl(dep.package.links.repository) } : undefined,
                safeExternalUrl(dep.package.links.homepage) ? { type: 'website', url: safeExternalUrl(dep.package.links.homepage) } : undefined
            ].filter(Boolean)
        })),
        dependencies: dependencies.map((dep) => ({
            ref: dep.package.id,
            dependsOn: subDependencyRefs(dep)
        }))
    }, null, 2);
}
function subDependencyRefs(dep) {
    return Array.from(new Set(Object.values(dep.graph.subDeps || {})
        .flatMap((group) => Object.values(group || {}))
        .filter((entry) => Array.isArray(entry) && entry.length >= 2 && (entry[1] === null || typeof entry[1] === 'string'))
        .map((entry) => entry[1])
        .filter((resolved) => Boolean(resolved))));
}
function spdxNamespace(data) {
    const stable = JSON.stringify({
        name: data.project.name || 'dependency-radar',
        version: data.project.version || '0.0.0',
        generatedAt: data.generatedAt,
        dependencies: Object.keys(data.dependencies || {}).sort()
    });
    return `https://www.dependency-radar.com/spdx/${(0, crypto_1.createHash)('sha256').update(stable).digest('hex').slice(0, 24)}`;
}
function renderSpdx(data) {
    const dependencies = Object.values(data.dependencies || {});
    const packages = dependencies.map((dep) => {
        const declared = dep.compliance.license.declared;
        const inferred = dep.compliance.license.inferred;
        const license = (declared === null || declared === void 0 ? void 0 : declared.valid) && declared.spdxId
            ? declared.spdxId
            : (inferred === null || inferred === void 0 ? void 0 : inferred.spdxId) || 'NOASSERTION';
        return {
            SPDXID: `SPDXRef-Package-${dep.package.id.replace(/[^A-Za-z0-9.-]/g, '-')}`,
            name: dep.package.name,
            versionInfo: dep.package.version,
            downloadLocation: dep.package.links.npm,
            filesAnalyzed: false,
            licenseConcluded: license,
            licenseDeclared: license,
            externalRefs: [
                {
                    referenceCategory: 'PACKAGE-MANAGER',
                    referenceType: 'purl',
                    referenceLocator: purl(dep)
                }
            ]
        };
    });
    return JSON.stringify({
        spdxVersion: 'SPDX-2.3',
        dataLicense: 'CC0-1.0',
        SPDXID: 'SPDXRef-DOCUMENT',
        name: `${data.project.name || 'dependency-radar'} dependency report`,
        documentNamespace: spdxNamespace(data),
        creationInfo: {
            created: data.generatedAt,
            creators: [`Tool: dependency-radar-${data.dependencyRadarVersion}`]
        },
        packages
    }, null, 2);
}
function defaultOutputName(format) {
    if (format === 'html')
        return 'dependency-radar.html';
    if (format === 'json')
        return 'dependency-radar.json';
    if (format === 'sarif')
        return 'dependency-radar.sarif';
    if (format === 'cyclonedx')
        return 'dependency-radar.cdx.json';
    return 'dependency-radar.spdx.json';
}
