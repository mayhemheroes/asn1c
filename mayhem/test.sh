#!/usr/bin/env bash
# asn1c/mayhem/test.sh — functional oracle for PATCH (GOLDEN-OUTPUT, anti-reward-hacking).
#
# Replicates asn1c's own tests/tests-asn1c-compiler/check-parsing.sh: for each checked-in
# *.asn1.-<flags> reference, run the NORMALLY-built compiler (built by mayhem/build.sh under
# build-tests/) on the source .asn1 with those flags and require its stdout/stderr to equal the
# golden reference BYTE-FOR-BYTE (after the same `found in ...` path scrub the upstream script uses).
#
# Oracle set = the BASELINE recorded by build.sh on the clean, unpatched build (build-tests/
# parsing-baseline.txt) — the references the current compiler actually reproduces. asn1c HEAD ships
# a handful of stale references that even a clean build doesn't match (upstream drift, not our bug);
# those are counted SKIPPED, never failed. A PATCH that breaks the parser/printer — or no-ops the
# program (empty output) — flips baseline-PASS cases to MISMATCH → failed>0 → non-zero exit. This is
# byte-for-byte golden comparison, NOT "ran without crashing".
#
# Does NOT compile: build.sh built the compiler + recorded the baseline; this only RUNS and reports.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

ASN1C="$SRC/build-tests/asn1c"
BASELINE="$SRC/build-tests/parsing-baseline.txt"
[ -x "$ASN1C" ]  || { echo "missing $ASN1C — run mayhem/build.sh first" >&2; exit 2; }
[ -f "$BASELINE" ] || { echo "missing $BASELINE — run mayhem/build.sh first" >&2; exit 2; }

passed=0; failed=0; skipped=0

# Compare one reference exactly as check-parsing.sh does.
matches_golden() {
  local ref="$1"
  local src flags old new
  src=$(echo "$ref" | sed -e 's/\.-[-a-zA-Z0-9=]*$//')
  flags=$(echo "$ref" | sed -e 's/.*\.-//')
  old=$(LANG=C sed -e 's/^found in .*/found in .../' < "$ref")
  new=$("$ASN1C" -S "$SRC/skeletons" -no-gen-OER -no-gen-PER "-$flags" "$src" 2>&1 \
        | LANG=C sed -e 's/^found in .*/found in .../')
  [ "$old" = "$new" ]
}

for ref in "$SRC"/tests/tests-asn1c-compiler/*.asn1.-*; do
  name=$(basename "$ref")
  if grep -qxF "$name" "$BASELINE"; then
    if matches_golden "$ref"; then
      echo "PASS parsing $name"; passed=$((passed+1))
    else
      echo "FAIL parsing $name (compiler output != golden reference)"; failed=$((failed+1))
    fi
  else
    echo "SKIP parsing $name (reference stale at upstream HEAD — not in clean baseline)"
    skipped=$((skipped+1))
  fi
done

echo "---"
echo "passed=$passed failed=$failed skipped=$skipped"
emit_ctrf "asn1c-check-parsing" "$passed" "$failed" "$skipped"
