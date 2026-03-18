#!/usr/bin/env node

const { spawnSync } = require("child_process");
const fs = require("fs");
const os = require("os");
const path = require("path");

const repoRoot = path.resolve(__dirname, "..");
const distCliPath = path.join(repoRoot, "dist", "cli.js");
const packageJsonPath = path.join(repoRoot, "package.json");
const fixturePath = path.join(repoRoot, "test-fixtures", "license-edge-cases");
const image = "node:14.21.3-bullseye";

/**
 * Raise a formatted error for fatal test failures.
 * @param {string} message - The error message to display.
 */
function fail(message) {
  throw new Error(message);
}

/**
 * Execute a command synchronously from the repository root and return the spawn result.
 *
 * @param {string} command - The executable or command to run.
 * @param {string[]} args - Array of arguments to pass to the command.
 * @param {Object} [options] - Optional execution settings.
 * @param {import('child_process').StdioOptions|string|Array} [options.stdio] - stdio configuration forwarded to spawnSync (defaults to `"pipe"`).
 * @param {NodeJS.ProcessEnv} [options.env] - Environment variables for the child process (defaults to `process.env`).
 * @returns {import('child_process').SpawnSyncReturns<string>} The object returned by spawnSync (includes `status`, `stdout`, `stderr`, and possibly `error`).
 * @throws {Error} If the spawnSync call failed to start the process (when `result.error` is set).
 */
function run(command, args, options = {}) {
  const result = spawnSync(command, args, {
    cwd: repoRoot,
    encoding: "utf8",
    stdio: options.stdio || "pipe",
    env: options.env || process.env,
  });

  if (result.error) {
    throw result.error;
  }

  return result;
}

/**
 * Write child-process output and raise an error if the result indicates failure.
 *
 * If `result.status` is non-zero, writes `result.stdout` to stdout and `result.stderr` to stderr when present, then raises an error with the provided message.
 * @param {import('child_process').SpawnSyncReturns<string|Buffer>} result - The synchronous spawn result to check.
 * @param {string} message - The error message to display on failure.
 */
function ensureSuccess(result, message) {
  if (result.status === 0) return;

  if (result.stdout) process.stdout.write(result.stdout);
  if (result.stderr) process.stderr.write(result.stderr);
  fail(message);
}

let tempRoot;
try {
  if (!fs.existsSync(distCliPath)) {
    fail("Missing dist/cli.js. Run `npm run build` before `npm run test:docker:node14`.");
  }

  if (!fs.existsSync(fixturePath)) {
    fail(`Missing fixture: ${fixturePath}`);
  }

  const dockerInfo = run("docker", ["info", "--format", "{{.ServerVersion}}"]);
  ensureSuccess(
    dockerInfo,
    "Docker is required for this test. Start Docker Desktop and rerun `npm run test:docker:node14`.",
  );

  tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "dependency-radar-node14-"));
  const npmCacheDir = path.join(tempRoot, "npm-cache");
  const artifactsDir = path.join(tempRoot, "artifacts");
  fs.mkdirSync(npmCacheDir, { recursive: true });
  fs.mkdirSync(artifactsDir, { recursive: true });

  const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, "utf8"));
  const expectedTarball = `${packageJson.name.replace(/^@/, "").replace(/\//g, "-")}-${packageJson.version}.tgz`;
  const installedPackageJsonPath = `./node_modules/${packageJson.name}/package.json`;

  console.log(`> Packing published artifact into ${artifactsDir}`);
  const packResult = run(
    "npm",
    ["pack", "--pack-destination", artifactsDir],
    {
      env: {
        ...process.env,
        npm_config_cache: npmCacheDir,
      },
    },
  );
  ensureSuccess(packResult, "npm pack failed.");

  const tarballPath = path.join(artifactsDir, expectedTarball);
  if (!fs.existsSync(tarballPath)) {
    const tgzFiles = fs.readdirSync(artifactsDir).filter((file) => file.endsWith(".tgz"));
    fail(
      `Packed tarball not found at ${tarballPath}. Found: ${tgzFiles.length ? tgzFiles.join(", ") : "none"}.`,
    );
  }

  const containerScript = [
    "set -euo pipefail",
    "rm -rf /tmp/app /tmp/fixture /tmp/report.json /tmp/scan.log",
    "mkdir -p /tmp/app",
    "cd /tmp/app",
    "npm init -y >/dev/null 2>&1",
    `npm install /artifacts/${expectedTarball} >/dev/null 2>&1`,
    `node -e 'const pkg=require(${JSON.stringify(installedPackageJsonPath)}); if (pkg.dependencies && Object.keys(pkg.dependencies).length) { throw new Error("runtime dependencies must stay empty"); }'`,
    "cp -R /repo/test-fixtures/license-edge-cases /tmp/fixture",
    "rm -f /tmp/fixture/dependency-radar.json /tmp/fixture/dependency-radar.html",
    "npx dependency-radar scan --project /tmp/fixture --offline --json --out /tmp/report.json >/tmp/scan.log 2>&1",
    "node -e 'const fs=require(\"fs\"); const report=JSON.parse(fs.readFileSync(\"/tmp/report.json\",\"utf8\")); const deps=Object.values(report.dependencies||{}).map((entry)=>entry && entry.package ? entry.package.name : null).filter(Boolean); if (!deps.includes(\"@dr-license/match-mit\")) { throw new Error(\"expected fixture dependency missing from report\"); } console.log(JSON.stringify({ node: process.version, dependencyCount: deps.length, reportPath: \"/tmp/report.json\" }, null, 2));'",
  ].join(" && ");

  console.log(`> Running Docker smoke test in ${image}`);
  const dockerRun = run(
    "docker",
    [
      "run",
      "--rm",
      "-v",
      `${repoRoot}:/repo:ro`,
      "-v",
      `${artifactsDir}:/artifacts:ro`,
      image,
      "bash",
      "-lc",
      containerScript,
    ],
    { stdio: "inherit" },
  );
  ensureSuccess(dockerRun, `Node 14 Docker smoke test failed in ${image}.`);

  console.log(`✔ Node 14 Docker smoke test passed (${image})`);
} catch (error) {
  const message = error instanceof Error ? error.message : String(error);
  console.error(`✖ ${message}`);
  process.exitCode = 1;
} finally {
  if (tempRoot) {
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
}
