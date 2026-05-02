#!/usr/bin/env node

const { execFileSync } = require("child_process");

const output = execFileSync("npm", ["pack", "--dry-run", "--json"], {
  encoding: "utf8",
  stdio: ["ignore", "pipe", "inherit"],
});

const [packument] = JSON.parse(output);
if (!packument || !Array.isArray(packument.files)) {
  throw new Error("npm pack did not return file metadata.");
}

const cli = packument.files.find((file) => file.path === "dist/cli.js");
if (!cli) {
  throw new Error("Package is missing dist/cli.js.");
}

const executableBits = cli.mode & 0o111;
if (executableBits === 0) {
  throw new Error(
    `dist/cli.js is not executable in the package tarball (mode ${cli.mode.toString(8)}).`
  );
}
