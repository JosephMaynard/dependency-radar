import type { AggregatedData, DependencyFinding, DependencyRecord } from './types';

export type ReportFormat = 'html' | 'json' | 'sarif' | 'cyclonedx' | 'spdx';

function purl(dep: DependencyRecord): string {
  const encodedName = dep.package.name.startsWith('@')
    ? dep.package.name
        .slice(1)
        .split('/')
        .map(encodeURIComponent)
        .join('/')
    : encodeURIComponent(dep.package.name);
  return `pkg:npm/${encodedName}@${encodeURIComponent(dep.package.version)}`;
}

function findingLevel(finding: DependencyFinding): 'error' | 'warning' | 'note' {
  if (finding.severity === 'error') return 'error';
  if (finding.severity === 'warning') return 'warning';
  return 'note';
}

export function renderSarif(data: AggregatedData): string {
  const findings = data.findings || [];
  const rules = new Map<string, any>();
  for (const finding of findings) {
    if (rules.has(finding.category)) continue;
    rules.set(finding.category, {
      id: finding.category,
      name: finding.category,
      shortDescription: { text: `Dependency Radar ${finding.category} finding` },
      helpUri: 'https://www.dependency-radar.com'
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
            informationUri: 'https://www.dependency-radar.com',
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
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: 'package.json' },
                region: { startLine: 1 }
              }
            }
          ]
        }))
      }
    ]
  }, null, 2);
}

function licenseIds(dep: DependencyRecord): Array<{ license: { id: string } } | { license: { name: string } }> {
  const declared = dep.compliance.license.declared;
  const inferred = dep.compliance.license.inferred;
  if (declared?.valid && declared.spdxId) return [{ license: { id: declared.spdxId } }];
  if (inferred?.spdxId) return [{ license: { id: inferred.spdxId } }];
  return [{ license: { name: 'UNKNOWN' } }];
}

export function renderCycloneDx(data: AggregatedData): string {
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
        { type: 'distribution', url: dep.package.links.npm },
        ...(dep.package.links.repository ? [{ type: 'vcs', url: dep.package.links.repository }] : []),
        ...(dep.package.links.homepage ? [{ type: 'website', url: dep.package.links.homepage }] : [])
      ]
    })),
    dependencies: dependencies.map((dep) => ({
      ref: dep.package.id,
      dependsOn: Object.values(dep.graph.subDeps || {})
        .flatMap((group) => Object.values(group || {}) as Array<[string, string | null]>)
        .map((entry) => entry[1])
        .filter((resolved): resolved is string => Boolean(resolved))
    }))
  }, null, 2);
}

export function renderSpdx(data: AggregatedData): string {
  const dependencies = Object.values(data.dependencies || {});
  const packages = dependencies.map((dep) => {
    const declared = dep.compliance.license.declared;
    const inferred = dep.compliance.license.inferred;
    const license = declared?.valid
      ? declared.spdxId
      : inferred?.spdxId || 'NOASSERTION';
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
    documentNamespace: `https://www.dependency-radar.com/spdx/${Date.now()}`,
    creationInfo: {
      created: data.generatedAt,
      creators: [`Tool: dependency-radar-${data.dependencyRadarVersion}`]
    },
    packages
  }, null, 2);
}

export function defaultOutputName(format: ReportFormat): string {
  if (format === 'html') return 'dependency-radar.html';
  if (format === 'json') return 'dependency-radar.json';
  if (format === 'sarif') return 'dependency-radar.sarif';
  if (format === 'cyclonedx') return 'dependency-radar.cdx.json';
  return 'dependency-radar.spdx.json';
}
