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

/**
 * Run the package manager's `outdated` command for a project, normalize the output, and optionally persist results to disk.
 *
 * Executes the appropriate `outdated` command for `npm`, `pnpm`, or `yarn` in the repository lockfile directory (if found) and normalizes the tool-specific output into a consistent map of package names to `{ current, latest, wanted }`.
 *
 * @param projectPath - Path to the project root where the command should be executed if no lockfile directory is found
 * @param tempDir - Directory used to write the tool-specific output file when persistence is enabled
 * @param tool - Package manager to run (`"npm" | "pnpm" | "yarn"`)
 * @param options - Optional settings
 * @param options.persistToDisk - When `false`, do not write any output file to `tempDir`; defaults to `true`
 * @returns A ToolResult containing `data` with the normalized outdated mapping on success, or `error` on failure. When persistence is enabled the result includes `file` with the path to the written JSON file.
 */
export async function runPackageOutdated(
  projectPath: string,
  tempDir: string,
  tool: "npm" | "pnpm" | "yarn",
  options: { persistToDisk?: boolean } = {},
): Promise<ToolResult<any>> {
  const persistToDisk = options.persistToDisk !== false;
  const targetFile = path.join(tempDir, `${tool}-outdated.json`);
  try {
    const { cmd, args, lockFiles } = buildOutdatedCommand(tool);
    const lockDir = await findLockDir(projectPath, lockFiles);
    const cwd = lockDir || projectPath;
    const result = await runCommand(cmd, args, { cwd });
    const parsed = parseJsonOutput(result.stdout);
    const normalized = normalizeOutdatedOutput(tool, parsed);
    if (normalized && typeof normalized === "object") {
      if (persistToDisk) {
        await writeJsonFile(targetFile, normalized);
      }
      return { ok: true, data: normalized, ...(persistToDisk ? { file: targetFile } : {}) };
    }
    if (tool === "yarn" && isYarnOutdatedUnsupported(result)) {
      if (persistToDisk) {
        await writeJsonFile(targetFile, {
          stdout: result.stdout,
          stderr: result.stderr,
          code: result.code,
        });
      }
      return {
        ok: false,
        error:
          'Yarn outdated is not available in this Yarn release (common on Yarn Berry).',
        ...(persistToDisk ? { file: targetFile } : {}),
      };
    }
    if (persistToDisk) {
      await writeJsonFile(targetFile, {
        stdout: result.stdout,
        stderr: result.stderr,
        code: result.code,
      });
    }
    return {
      ok: false,
      error: `Failed to parse ${tool} outdated output`,
      ...(persistToDisk ? { file: targetFile } : {}),
    };
  } catch (err: any) {
    if (persistToDisk) {
      await writeJsonFile(targetFile, { error: String(err) });
    }
    return {
      ok: false,
      error: `${tool} outdated failed: ${String(err)}`,
      ...(persistToDisk ? { file: targetFile } : {}),
    };
  }
}
