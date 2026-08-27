import { describe, expect, it } from "vitest";
import {
  buildSlideModel,
  type SlideDependencyRecord,
  type SlideInputData,
} from "./slideModel";

function dep(
  overrides: Partial<SlideDependencyRecord> & {
    name: string;
    version?: string;
  },
): SlideDependencyRecord {
  const { name, version, ...rest } = overrides;
  return {
    package: { name, version: version || "1.0.0", installSize: null },
    compliance: { licenseRisk: "green" },
    upgrade: {},
    usage: { direct: false },
    ...rest,
  };
}

function input(
  deps: SlideDependencyRecord[],
  extras: Partial<SlideInputData> = {},
): SlideInputData {
  const dependencies: Record<string, SlideDependencyRecord> = {};
  for (const record of deps) {
    dependencies[record.package.name + "@" + record.package.version] = record;
  }
  return {
    generatedAt: "2026-08-21T09:20:34.670Z",
    dependencyRadarVersion: "1.2.1",
    project: { name: "sample" },
    summary: {
      dependencyCount: deps.length,
      directCount: deps.filter((d) => d.usage.direct).length,
      transitiveCount: deps.filter((d) => !d.usage.direct).length,
    },
    dependencies,
    ...extras,
  };
}

describe("buildSlideModel", () => {
  it("counts vulnerable packages but dedupes advisory ids across records", () => {
    const model = buildSlideModel(
      input([
        dep({
          name: "a",
          security: {
            summary: { critical: 0, high: 1, moderate: 0, low: 0, highest: "high" },
            advisories: [{ id: "GHSA-1" }],
          },
        }),
        dep({
          name: "b",
          security: {
            summary: { critical: 0, high: 0, moderate: 1, low: 0, highest: "moderate" },
            advisories: [{ id: "GHSA-1" }],
          },
        }),
        dep({ name: "c" }),
      ]),
    );
    expect(model.vulnerabilities.count).toBe(2);
    expect(model.vulnerabilities.detail).toBe("1 advisory · worst high");
    expect(model.vulnerabilities.tone).toBe("red");
  });

  it("marks audit-less scans as not checked instead of clean", () => {
    const model = buildSlideModel(
      input([dep({ name: "a" })], {
        scanStatus: { collectors: { audit: "unavailable" } },
      }),
    );
    expect(model.vulnerabilities.count).toBe(-1);
    expect(model.vulnerabilities.tone).toBe("gray");
  });

  it("treats reports predating scanStatus as fully collected", () => {
    const model = buildSlideModel(
      input([dep({ name: "a", maintenance: { status: "active", attempted: true } })]),
    );
    expect(model.vulnerabilities.count).toBe(0);
    expect(model.maintenance.count).toBe(0);
  });

  it("marks a partial audit as not checked rather than a definitive count", () => {
    const model = buildSlideModel(
      input([dep({ name: "a" })], {
        scanStatus: { collectors: { audit: "partial" } },
      }),
    );
    expect(model.vulnerabilities.count).toBe(-1);
  });

  it("marks maintenance as not checked when no lookup was ever attempted", () => {
    const model = buildSlideModel(input([dep({ name: "a" })]));
    expect(model.maintenance.count).toBe(-1);
    expect(model.maintenance.tone).toBe("gray");
  });

  it("summarises maintenance concerns with a status breakdown", () => {
    const model = buildSlideModel(
      input([
        dep({ name: "a", maintenance: { status: "stale", attempted: true } }),
        dep({ name: "b", maintenance: { status: "stale", attempted: true } }),
        dep({ name: "c", maintenance: { status: "slowing", attempted: true } }),
        dep({ name: "d", maintenance: { status: "active", attempted: true } }),
      ]),
    );
    expect(model.maintenance.count).toBe(3);
    expect(model.maintenance.detail).toBe("2 stale · 1 slowing");
    expect(model.maintenance.tone).toBe("amber");
  });

  it("escalates maintenance tone when packages are deprecated or archived", () => {
    const model = buildSlideModel(
      input([dep({ name: "a", maintenance: { status: "deprecated", attempted: true } })]),
    );
    expect(model.maintenance.detail).toBe("1 deprecated or archived");
    expect(model.maintenance.tone).toBe("red");
  });

  it("counts licence issues as any non-green risk, high risk as red", () => {
    const model = buildSlideModel(
      input([
        dep({ name: "a", compliance: { licenseRisk: "amber" } }),
        dep({ name: "b", compliance: { licenseRisk: "red" } }),
        dep({ name: "c", compliance: { licenseRisk: "green" } }),
      ]),
    );
    expect(model.licenses.count).toBe(2);
    expect(model.licenses.detail).toBe("1 high risk");
    expect(model.licenses.tone).toBe("red");
  });

  it("counts upgrade blockers including Node target blockers", () => {
    const model = buildSlideModel(
      input([
        dep({ name: "a", upgrade: { blocksNodeMajor: "18" } }),
        dep({ name: "b", upgrade: { blockers: ["peer"] } }),
        dep({ name: "c" }),
      ]),
    );
    expect(model.blockers.count).toBe(2);
    expect(model.blockers.detail).toBe("1 block the Node target");
  });

  it("counts duplicate installed versions per package name", () => {
    const model = buildSlideModel(
      input([
        dep({ name: "a", version: "1.0.0" }),
        dep({ name: "a", version: "2.0.0" }),
        dep({ name: "a", version: "3.0.0" }),
        dep({ name: "b", version: "1.0.0" }),
      ]),
    );
    expect(model.duplicates.count).toBe(1);
    expect(model.duplicates.detail).toBe("2 extra installs");
  });

  it("sums measured install sizes and ranks the largest blocks", () => {
    const model = buildSlideModel(
      input([
        dep({
          name: "big",
          package: { name: "big", version: "1.0.0", installSize: { totalBytes: 900 } },
        }),
        dep({
          name: "small",
          package: { name: "small", version: "1.0.0", installSize: { totalBytes: 100 } },
        }),
      ]),
    );
    expect(model.totalInstallBytes).toBe(1000);
    expect(model.measuredPackageCount).toBe(2);
    expect(model.sizeBlocks[0]).toEqual({ name: "big", bytes: 900, share: 0.9 });
    expect(model.sizeOtherBytes).toBe(0);
  });

  it("keeps zero-byte packages in the total but never as treemap blocks", () => {
    const model = buildSlideModel(
      input([
        dep({
          name: "real",
          package: { name: "real", version: "1.0.0", installSize: { totalBytes: 500 } },
        }),
        dep({
          name: "empty",
          package: { name: "empty", version: "1.0.0", installSize: { totalBytes: 0 } },
        }),
      ]),
    );
    expect(model.measuredPackageCount).toBe(2);
    expect(model.sizeBlocks.map((b) => b.name)).toEqual(["real"]);
  });

  it("reports install size as unmeasured when no package was measured", () => {
    const model = buildSlideModel(input([dep({ name: "a" })]));
    expect(model.totalInstallBytes).toBe(-1);
    expect(model.sizeBlocks).toEqual([]);
  });
});
