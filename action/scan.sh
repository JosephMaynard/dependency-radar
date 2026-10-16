#!/usr/bin/env bash
# Runs one dependency-radar scan that writes the JSON report. --fail-on is
# passed straight through, so the exit code means exactly what it means for
# the CLI: 0 passed, 1 policy violated, 2 incomplete evidence or bad usage.
# The step itself always succeeds; action.yml applies the exit code at the
# very end, after the comment is posted.
#
# When DR_BASELINE points at an earlier JSON report, a second run of
# `compare` produces the change list and evaluates compare-only rules such as
# new-install-script.
set -uo pipefail

: "${DR_CLI:?DR_CLI is required}"
: "${DR_OUT_DIR:?DR_OUT_DIR is required}"
project="${DR_PROJECT:-.}"

flags=(--project "$project" --quiet)
if [ "${DR_OFFLINE:-false}" = "true" ]; then flags+=(--offline); fi
if [ "${DR_NO_MAINTENANCE:-false}" = "true" ]; then flags+=(--no-maintenance); fi
if [ -n "${DR_FAIL_ON:-}" ]; then flags+=(--fail-on "$DR_FAIL_ON"); fi

json="$DR_OUT_DIR/dependency-radar.json"
scan_log="$DR_OUT_DIR/scan.log"

echo "::group::dependency-radar scan"
node "$DR_CLI" scan --json --out "$json" "${flags[@]}" 2>&1 | tee "$scan_log"
code=${PIPESTATUS[0]}
echo "::endgroup::"
echo "Scan exit code: $code"

compare_log=""
if [ -n "${DR_BASELINE:-}" ]; then
  if [ -f "$DR_BASELINE" ]; then
    compare_log="$DR_OUT_DIR/compare.log"
    echo "::group::dependency-radar compare $DR_BASELINE"
    node "$DR_CLI" compare "$DR_BASELINE" "${flags[@]}" 2>&1 | tee "$compare_log"
    compare_code=${PIPESTATUS[0]}
    echo "::endgroup::"
    echo "Compare exit code: $compare_code"
    # Keep the worse result: 2 (could not check) beats 1 (violated) beats 0.
    if [ "$compare_code" -eq 2 ] || [ "$code" -eq 2 ]; then
      code=2
    elif [ "$compare_code" -ne 0 ] || [ "$code" -ne 0 ]; then
      code=1
    fi
  else
    echo "::warning::baseline is set to '$DR_BASELINE' but no file exists there, so the comparison was skipped."
  fi
fi

{
  echo "exit-code=$code"
  echo "json-path=$( [ -f "$json" ] && echo "$json" )"
  echo "scan-log=$scan_log"
  echo "compare-log=$compare_log"
} >> "${GITHUB_OUTPUT:-/dev/stdout}"
exit 0
