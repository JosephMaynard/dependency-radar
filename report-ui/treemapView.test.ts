import { describe, expect, it } from "vitest";
import { squarify } from "./treemapView";

const area = (r: { w: number; h: number }): number => r.w * r.h;

describe("squarify", () => {
  it("keeps areas proportional to weights and tiles the box exactly", () => {
    const placed = squarify(
      [
        { id: 0, weight: 6 },
        { id: 1, weight: 3 },
        { id: 2, weight: 1 },
      ],
      0,
      0,
      100,
      50,
    );
    expect(placed).toHaveLength(3);
    const total = placed.reduce((sum, r) => sum + area(r), 0);
    expect(total).toBeCloseTo(100 * 50, 6);
    const byId = new Map(placed.map((r) => [r.id, r]));
    expect(area(byId.get(0)!)).toBeCloseTo(3000, 6);
    expect(area(byId.get(1)!)).toBeCloseTo(1500, 6);
    expect(area(byId.get(2)!)).toBeCloseTo(500, 6);
  });

  it("reserves the parent's own unit via a self item", () => {
    // A parent of dominator weight 3 has two weight-1 children plus itself.
    // With the phantom self item each child covers one THIRD of the content
    // box, not half — nested areas keep meaning "packages".
    const placed = squarify(
      [
        { id: 0, weight: 1 },
        { id: 1, weight: 1 },
        { id: -3, weight: 1 },
      ],
      0,
      0,
      90,
      30,
    );
    const kids = placed.filter((r) => r.id >= 0);
    expect(kids).toHaveLength(2);
    for (const kid of kids) {
      expect(area(kid)).toBeCloseTo((90 * 30) / 3, 6);
    }
  });

  it("drops zero-weight items and survives empty input", () => {
    expect(squarify([], 0, 0, 10, 10)).toEqual([]);
    const placed = squarify(
      [
        { id: 0, weight: 0 },
        { id: 1, weight: 2 },
      ],
      0,
      0,
      10,
      10,
    );
    expect(placed.map((r) => r.id)).toEqual([1]);
    expect(area(placed[0])).toBeCloseTo(100, 6);
  });
});
