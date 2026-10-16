#!/usr/bin/env bash
# Installs the requested dependency-radar into a private folder under
# RUNNER_TEMP, so the scan step can run its CLI and the render step can load
# its modules from a known path. dependency-radar has no runtime
# dependencies, so this is a single package download.
#
# DR_VERSION accepts:
#   latest (default), a version (1.4.0), a range (1) or a dist-tag
#   a full npm spec: dependency-radar@next, file:..., git+..., https://...
#   a path to a packed tarball: ./dependency-radar-1.4.0.tgz (used to dogfood)
set -euo pipefail

spec="${DR_VERSION:-latest}"
case "$spec" in
  "" | latest)
    pkg="dependency-radar@latest" ;;
  dependency-radar@* | file:* | git+* | http://* | https://*)
    pkg="$spec" ;;
  *.tgz | */*)
    if [ ! -e "$spec" ]; then
      echo "::error::version is set to '$spec', which looks like a path, but nothing exists there."
      exit 2
    fi
    pkg="$(cd "$(dirname "$spec")" && pwd)/$(basename "$spec")" ;;
  *)
    pkg="dependency-radar@$spec" ;;
esac

base="${RUNNER_TEMP:-${TMPDIR:-/tmp}}"
prefix="$(mktemp -d "$base/dependency-radar-cli.XXXXXX")"

echo "Installing $pkg"
npm install \
  --prefix "$prefix" \
  --no-save \
  --no-package-lock \
  --no-audit \
  --no-fund \
  --ignore-scripts \
  --loglevel=error \
  "$pkg"

package_dir="$prefix/node_modules/dependency-radar"
if [ ! -f "$package_dir/dist/cli.js" ]; then
  echo "::error::Installed $pkg but $package_dir/dist/cli.js is missing."
  exit 2
fi
installed_version="$(node -p "require(process.argv[1]).version" "$package_dir/package.json")"
echo "Using dependency-radar $installed_version"

out_dir="$(mktemp -d "$base/dependency-radar-out.XXXXXX")"

{
  echo "package-dir=$package_dir"
  echo "cli=$package_dir/dist/cli.js"
  echo "version=$installed_version"
  echo "out-dir=$out_dir"
} >> "${GITHUB_OUTPUT:-/dev/stdout}"
