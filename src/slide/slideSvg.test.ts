import { describe, expect, it } from "vitest";
import { buildSlideModel, type SlideInputData } from "./slideModel";
import {
  buildSlideSvg,
  formatSlideBytes,
  SLIDE_HEIGHT,
  SLIDE_WIDTH,
} from "./slideSvg";

function sampleInput(): SlideInputData {
  return {
    generatedAt: "2026-08-21T09:20:34.670Z",
    dependencyRadarVersion: "1.2.1",
    project: { name: "acme <&> app" },
    summary: { dependencyCount: 2, directCount: 1, transitiveCount: 1 },
    dependencies: {
      "left-pad@1.0.0": {
        package: {
          name: "left<pad>&co",
          version: "1.0.0",
          installSize: { totalBytes: 5 * 1024 * 1024 },
        },
        compliance: { licenseRisk: "amber" },
        upgrade: { blockers: ["peer"] },
        maintenance: { status: "stale" },
        usage: { direct: true },
      },
      "b@1.0.0": {
        package: {
          name: "b",
          version: "1.0.0",
          installSize: { totalBytes: 1024 * 1024 },
        },
        compliance: { licenseRisk: "green" },
        upgrade: {},
        usage: { direct: false },
      },
    },
  };
}

describe("buildSlideSvg", () => {
  it("renders a self-contained SVG with no external references", () => {
    const svg = buildSlideSvg(buildSlideModel(sampleInput()), "dark");
    expect(svg.startsWith("<svg ")).toBe(true);
    expect(svg.endsWith("</svg>")).toBe(true);
    expect(svg).toContain('width="' + SLIDE_WIDTH + '"');
    expect(svg).toContain('height="' + SLIDE_HEIGHT + '"');
    // Self-containment: nothing the file cannot resolve on its own.
    expect(svg).not.toContain("http://www.w3.org/1999/xlink");
    expect(svg).not.toContain("foreignObject");
    expect(svg).not.toContain("var(--");
    expect(svg).not.toMatch(/href="(?!#)/);
  });

  it("escapes XML-hostile project and package names exactly once", () => {
    const svg = buildSlideSvg(buildSlideModel(sampleInput()), "dark");
    expect(svg).toContain("acme &lt;&amp;&gt; app");
    expect(svg).not.toContain("left<pad>");
    // Escaping is centralised in the text() helper; a second layer at a
    // call site would show up as &amp;lt;.
    expect(svg).not.toContain("&amp;lt;");
    expect(svg).not.toContain("&amp;amp;");
  });

  it("differs between themes only in colour, not structure", () => {
    const dark = buildSlideSvg(buildSlideModel(sampleInput()), "dark");
    const light = buildSlideSvg(buildSlideModel(sampleInput()), "light");
    expect(dark).not.toBe(light);
    const shape = (svg: string): string =>
      svg.replace(/#[0-9a-f]{6}/gi, "#").replace(/rgba\([^)]*\)/g, "rgba()");
    expect(shape(dark)).toBe(shape(light));
  });

  it("says Not checked when a collector never ran, rather than showing zero", () => {
    const data = sampleInput();
    data.scanStatus = { collectors: { audit: "skipped" } };
    const svg = buildSlideSvg(buildSlideModel(data), "dark");
    expect(svg).toContain("Not checked in this scan");
  });

  it("carries the partial-scan caveat into the exported artifact", () => {
    const data = sampleInput();
    data.scanStatus = { collectors: { dependencyTree: "partial" } };
    const svg = buildSlideSvg(buildSlideModel(data), "dark");
    expect(svg).toContain("counts are lower bounds");
    const complete = buildSlideSvg(buildSlideModel(sampleInput()), "dark");
    expect(complete).not.toContain("counts are lower bounds");
  });

  it("accounts for the whole measured total in the treemap", () => {
    const svg = buildSlideSvg(buildSlideModel(sampleInput()), "dark");
    expect(svg).toContain("6.0 MB");
  });
});

describe("formatSlideBytes", () => {
  it("matches the report's byte formatting and adds a GB step", () => {
    expect(formatSlideBytes(512)).toBe("512 B");
    expect(formatSlideBytes(2048)).toBe("2 kB");
    expect(formatSlideBytes(93663907)).toBe("89.3 MB");
    expect(formatSlideBytes(3 * 1024 * 1024 * 1024)).toBe("3.0 GB");
  });
});
