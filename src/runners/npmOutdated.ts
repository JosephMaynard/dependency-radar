import path from "path";
import { ToolResult } from "../types";
import {
  runCommand,
  writeJsonFile,
  findLockDir,
  parseJsonOutput,
} from "../utils";

function normalizeOutdatedOutput(
  tool: "npm" | "pnpm" | "yarn",
  data: any,
): any | undefined {
  if (!data) return undefined;
  if (typeof data === "object" && !Array.isArray(data) && !data.type)
    return data;

  // Yarn JSONL table output (classic) must be checked before generic array parsing.
  const entries = Array.isArray(data) ? data : [data];
  const tableEntry = entries.find(
    (e) => e && typeof e === "object" && (e.type === "table" || e.data?.body),
  );
  const table = tableEntry?.data || tableEntry;
  if (table && Array.isArray(table.head) && Array.isArray(table.body)) {
    const head = table.head.map((h: any) => String(h).toLowerCase());
    const idx = {
      name: head.findIndex(
        (h: string) => h.includes("package") || h.includes("name"),
      ),
      current: head.findIndex((h: string) => h.includes("current")),
      latest: head.findIndex((h: string) => h.includes("latest")),
      wanted: head.findIndex((h: string) => h.includes("wanted")),
    };
    const out: Record<string, any> = {};
    for (const row of table.body) {
      if (!Array.isArray(row)) continue;
      const name = idx.name >= 0 ? String(row[idx.name]) : "";
      if (!name) continue;
      out[name] = {
        current: idx.current >= 0 ? String(row[idx.current]) : undefined,
        latest: idx.latest >= 0 ? String(row[idx.latest]) : undefined,
        wanted: idx.wanted >= 0 ? String(row[idx.wanted]) : undefined,
      };
    }
    return Object.keys(out).length > 0 ? out : undefined;
  }

  if (Array.isArray(data)) {
    // pnpm often returns arrays of rows
    const out: Record<string, any> = {};
    for (const entry of data) {
      if (!entry || typeof entry !== "object") continue;
      const name = entry.name || entry.packageName;
      if (typeof name !== "string" || !name.trim()) continue;
      out[name] = {
        current: entry.current || entry.currentVersion || entry.from,
        latest: entry.latest || entry.latestVersion || entry.to,
        wanted: entry.wanted,
      };
    }
    return Object.keys(out).length > 0 ? out : undefined;
  }

  if (tool === "pnpm" && data.outdated) return data.outdated;
  return undefined;
}

function isYarnOutdatedUnsupported(result: {
  stdout: string;
  stderr: string;
}): boolean {
  const output = `${result.stdout}\n${result.stderr}`;
  return /Couldn't find a script named "outdated"/i.test(output);
}

function buildOutdatedCommand(tool: "npm" | "pnpm" | "yarn"): {
  cmd: string;
  args: string[];
  lockFiles: string[];
} {
  if (tool === "pnpm") {
    return {
      cmd: "pnpm",
      args: ["outdated", "--json"],
      lockFiles: ["pnpm-lock.yaml"],
    };
  }
  if (tool === "yarn") {
    return {
      cmd: "yarn",
      args: ["outdated", "--json"],
      lockFiles: ["yarn.lock"],
    };
  }
  return {
    cmd: "npm",
    args: ["outdated", "--json", "--long"],
    lockFiles: ["package-lock.json", "npm-shrinkwrap.json"],
  };
}

export async function runPackageOutdated(
  projectPath: string,
  tempDir: string,
  tool: "npm" | "pnpm" | "yarn",
): Promise<ToolResult<any>> {
  const targetFile = path.join(tempDir, `${tool}-outdated.json`);
  try {
    const { cmd, args, lockFiles } = buildOutdatedCommand(tool);
    const lockDir = await findLockDir(projectPath, lockFiles);
    const cwd = lockDir || projectPath;
    const result = await runCommand(cmd, args, { cwd });
    const parsed = parseJsonOutput(result.stdout);
    const normalized = normalizeOutdatedOutput(tool, parsed);
    if (normalized && typeof normalized === "object") {
      await writeJsonFile(targetFile, normalized);
      return { ok: true, data: normalized, file: targetFile };
    }
    if (tool === "yarn" && isYarnOutdatedUnsupported(result)) {
      await writeJsonFile(targetFile, {
        stdout: result.stdout,
        stderr: result.stderr,
        code: result.code,
      });
      return {
        ok: false,
        error:
          'Yarn outdated is not available in this Yarn release (common on Yarn Berry).',
        file: targetFile,
      };
    }
    await writeJsonFile(targetFile, {
      stdout: result.stdout,
      stderr: result.stderr,
      code: result.code,
    });
    return {
      ok: false,
      error: `Failed to parse ${tool} outdated output`,
      file: targetFile,
    };
  } catch (err: any) {
    await writeJsonFile(targetFile, { error: String(err) });
    return {
      ok: false,
      error: `${tool} outdated failed: ${String(err)}`,
      file: targetFile,
    };
  }
}
