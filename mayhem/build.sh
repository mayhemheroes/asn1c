#!/usr/bin/env bash
# asn1c/mayhem/build.sh — autotools build (ASan+UBSan) of asn1c's ASN.1 parser libraries + the
# asn1_parse_fuzzer libFuzzer harness (and its non-fuzzer -standalone reproducer), PLUS asn1c's own
# golden-output compiler test suite built with NORMAL flags so mayhem/test.sh only RUNS it.
#
# asn1c is an ASN.1 -> C compiler. The classic, most reliable fuzz surface is its FRONT END — the
# lexer + yacc grammar that turns ASN.1 SOURCE TEXT into a module tree (asn1p_parse_buffer, in
# libasn1parser). The harness drives that in-process (see mayhem/asn1_parse_fuzzer.c).
#
# Sanitizer note (benign-UB relax — see PORTING.md "benign UB that floods under halting UBSan"):
# libasn1parser/asn1p_integer.c defines ASN_INTEGER_MAX as `(asn1c_integer_t)1 << 127` on a 128-bit
# type, tripping UBSan's `shift` check on essentially EVERY run (even valid input) and aborting before
# the fuzzer can explore. We relax ONLY that one check (-fno-sanitize=shift) and keep ASan + the rest
# of UBSan ON and HALTING, so real memory/UB defects still crash. (A valid input then runs to exit 0.)
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' (empty) — it must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# Build knobs from the ENV (overridable). SANITIZER_FLAGS uses `=` (not `:=`) so an explicit empty
# --build-arg SANITIZER_FLAGS= is honored (builds with NO sanitizers, the program's natural crash).
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer -g}"
# DEBUG_FLAGS: DWARF ≤ 3 required (Mayhem triage can't read DWARF ≥ 4; clang-19 plain -g emits DWARF-5).
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"

# Relax ONLY the benign 128-bit-shift UBSan check for the FUZZ build (kept narrow; ASan + the rest of
# UBSan stay halting). Skip the relax when sanitizers are explicitly disabled (empty SANITIZER_FLAGS).
FUZZ_SAN_FLAGS="$SANITIZER_FLAGS"
if [ -n "$SANITIZER_FLAGS" ]; then
  FUZZ_SAN_FLAGS="$SANITIZER_FLAGS -fno-sanitize=shift"
fi
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS

cd "$SRC"

# ---------------------------------------------------------------------------
# IDEMPOTENCY: if the tree was already built (Makefile present from a prior run), distclean first so
# a second offline re-run starts from a clean slate. autoreconf is always re-run to regenerate any
# stale autoconf/automake outputs — this is safe and ensures configure reflects the current sources.
# ---------------------------------------------------------------------------
if [ -f Makefile ]; then
  make distclean || true
fi
autoreconf -iv

# asn1c's autotools build is in-tree; the parser/printer libs build under */.libs/*.a. We build the
# test suite FIRST with NORMAL flags, stash the test binary, `make distclean`, then the sanitized
# build the harness links against.

# ---------------------------------------------------------------------------
# 0) asn1c's OWN functional suite with the project's NORMAL flags (no sanitizers): the compiler binary
#    + the parsing golden-output test driver (tests/tests-asn1c-compiler/check-parsing.sh compares the
#    compiler's stdout/stderr against checked-in *.asn1.-<flags> golden references). We just need the
#    asn1c binary built normally; stash it where test.sh looks. test.sh then RUNS check-parsing.sh.
# ---------------------------------------------------------------------------
./configure CC="$CC"
make "-j$MAYHEM_JOBS"
mkdir -p "$SRC/build-tests"
cp "$SRC/asn1c/asn1c" "$SRC/build-tests/asn1c"     # the normally-built compiler the oracle runs

# Record the golden-output BASELINE on this clean, unpatched build: which checked-in
# *.asn1.-<flags> references the normally-built compiler currently reproduces byte-for-byte.
# asn1c HEAD ships some references that drift from current compiler output (the maintainers
# don't always regenerate them); those are NOT our regressions, so test.sh treats the
# baseline-passing set as the oracle and SKIPS the known-stale ones. A PATCH that breaks the
# parser/printer (or no-ops the program) flips baseline-PASS cases to FAIL → test.sh fails.
# This replicates check-parsing.sh's per-case comparison exactly (same flags + `found in` scrub).
BASELINE="$SRC/build-tests/parsing-baseline.txt"
: > "$BASELINE"
for ref in "$SRC"/tests/tests-asn1c-compiler/*.asn1.-*; do
  src=$(echo "$ref" | sed -e 's/\.-[-a-zA-Z0-9=]*$//')
  flags=$(echo "$ref" | sed -e 's/.*\.-//')
  old=$(LANG=C sed -e 's/^found in .*/found in .../' < "$ref")
  # asn1c exits nonzero on the SE/NP error-case sources by design; the GOLDEN reference captures
  # that very stderr, so a byte-equal match (not the exit code) is the oracle. Guard the substitution
  # so its exit can't trip `set -e`/pipefail.
  new=$({ "$SRC/build-tests/asn1c" -S "$SRC/skeletons" -no-gen-OER -no-gen-PER "-$flags" "$src" 2>&1 \
        | LANG=C sed -e 's/^found in .*/found in .../'; } || true)
  [ "$old" = "$new" ] && echo "$(basename "$ref")" >> "$BASELINE"
done
echo "build.sh: golden-output baseline = $(wc -l < "$BASELINE") passing references"

make distclean

# ---------------------------------------------------------------------------
# 1) Build asn1c WITH the (shift-relaxed) sanitizer flags so the FUZZED parser code is instrumented.
#    Produces the static libs the harness links: libasn1parser.a + libasn1common.a, and the
#    sanitized asn1c COMPILER binary (the file-input Mayhem target /mayhem/asn1c-fuzz).
#
#    LeakSanitizer OFF for the asn1c-fuzz target: asn1c is a short-lived compiler that never frees by
#    design (it relies on process exit to reclaim memory), so LSan (which runs at exit as part of ASan)
#    reports benign "leaks" on essentially EVERY input, flooding the fuzzer with spurious crashes. We
#    disable ONLY leak detection by baking a weak __asan_default_options into the binary — this holds no
#    matter how the binary is launched and, unlike a Mayhemfile ASAN_OPTIONS, does NOT override Mayhem's
#    own runtime ASAN_OPTIONS (abort_on_error=1/symbolize=0/...). The rest of ASan (heap/stack/global
#    overflow + use-after-free) and all of (shift-relaxed) UBSan stay ON and HALTING.
#
#    We inject the override object into asn1c's libtool link via LDFLAGS: automake appends
#    $(AM_LDFLAGS) $(LDFLAGS) to the final program link, so a plain .o named there is linked into the
#    asn1c binary regardless of the (libtool .la) object set — autotools-agnostic, no object-name list
#    to keep in sync. Skip when sanitizers are explicitly disabled (empty SANITIZER_FLAGS).
# ---------------------------------------------------------------------------
ASAN_OPTS_O=""
ASAN_OPTS_LDFLAGS=""
if printf '%s' "$FUZZ_SAN_FLAGS" | grep -q address; then
  cat > "$SRC/mayhem-asan-opts.c" <<'EOF'
/* Disable LeakSanitizer for asn1c-fuzz: asn1c is a compiler that never frees by design, so LSan would
   report benign leaks on nearly every input. Weak __asan_default_options keeps the rest of ASan + UBSan
   active and halting, and (unlike Mayhemfile ASAN_OPTIONS) does not override Mayhem's runtime options. */
const char *__asan_default_options(void) { return "detect_leaks=0"; }
EOF
  $CC $FUZZ_SAN_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem-asan-opts.c" -o "$SRC/mayhem-asan-opts.o"
  ASAN_OPTS_O="$SRC/mayhem-asan-opts.o"
  ASAN_OPTS_LDFLAGS="$ASAN_OPTS_O"
fi

autoreconf -iv
# -fsanitize=fuzzer-no-link adds SanitizerCoverage inline-8-bit-counters to every compiled TU so
# libFuzzer has coverage feedback from the parser/common library code (not just the thin harness).
# Without it the build produces only 11 counters (harness only) and libFuzzer runs blind, yielding
# 0 useful edges. fuzzer-no-link adds instrumentation only; the fuzzer runtime is linked later via
# $LIB_FUZZING_ENGINE. This flag is safe to pass to configure because it affects only the TU-level
# counter injection and does not change binary semantics or break the asn1c compiler target.
./configure CC="$CC" CFLAGS="$FUZZ_SAN_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link" LDFLAGS="$ASAN_OPTS_LDFLAGS"
make "-j$MAYHEM_JOBS"

PARSER_A="$SRC/libasn1parser/.libs/libasn1parser.a"
COMMON_A="$SRC/libasn1common/.libs/libasn1common.a"
INCS="-I$SRC/libasn1parser -I$SRC/libasn1common"

# ---------------------------------------------------------------------------
# 2) The fuzz harness, built TWICE: the libFuzzer binary (the Mayhem target) and a non-fuzzer
#    standalone reproducer (one input file, runs LLVMFuzzerTestOneInput once). Both respect the
#    sanitizer flags. Plain C harness, so $CC links both; $STANDALONE_FUZZ_MAIN has C linkage.
# ---------------------------------------------------------------------------
$CC $FUZZ_SAN_FLAGS $DEBUG_FLAGS $INCS \
    "$SRC/mayhem/asn1_parse_fuzzer.c" $LIB_FUZZING_ENGINE "$PARSER_A" "$COMMON_A" \
    -o /mayhem/asn1_parse_fuzzer

$CC $FUZZ_SAN_FLAGS $DEBUG_FLAGS $INCS \
    "$SRC/mayhem/asn1_parse_fuzzer.c" "$STANDALONE_FUZZ_MAIN" "$PARSER_A" "$COMMON_A" \
    -o /mayhem/asn1_parse_fuzzer-standalone

# ---------------------------------------------------------------------------
# 3) Whole-binary file-input target: the asn1c COMPILER fed an .asn1 source file (the original
#    integration's surface, target name `asn1c`). The sanitized compiler is the one make just built
#    (instrumented, shift-relaxed, with the weak __asan_default_options=detect_leaks=0 baked in via
#    the LDFLAGS object above); stash it at the stable path /mayhem/asn1c-fuzz. The Mayhemfile points
#    -S at the baked skeletons and runs in a scratch cwd (asn1c writes generated files to cwd); it sets
#    NO ASAN_OPTIONS — Mayhem owns the runtime options and the baked default supplies detect_leaks=0.
# ---------------------------------------------------------------------------
cp "$SRC/asn1c/asn1c" /mayhem/asn1c-fuzz

# Verify the leak-off override actually made it into the binary when ASan is active (catches a libtool
# link that dropped the LDFLAGS object). NB: write nm to a temp file and grep THAT — `nm | grep -q`
# under `set -o pipefail` returns the SIGPIPE status (nm killed when grep exits on first match), which
# would spuriously look like "not found". When ASan is off ($ASAN_OPTS_O empty) the symbol isn't
# expected, so skip the check.
if [ -n "$ASAN_OPTS_O" ]; then
  nm /mayhem/asn1c-fuzz > /tmp/asn1c-fuzz.nm 2>/dev/null || true
  if ! grep -q __asan_default_options /tmp/asn1c-fuzz.nm; then
    echo "build.sh: __asan_default_options not in libtool link; relinking asn1c-fuzz with the override"
    $CC $FUZZ_SAN_FLAGS $DEBUG_FLAGS -o /mayhem/asn1c-fuzz \
        "$SRC"/asn1c/asn1c.o "$ASAN_OPTS_O" \
        "$SRC/libasn1print/.libs/libasn1print.a" \
        "$SRC/libasn1fix/.libs/libasn1fix.a" \
        "$SRC/libasn1compiler/.libs/libasn1compiler.a" \
        "$SRC/libasn1parser/.libs/libasn1parser.a" \
        "$SRC/libasn1common/.libs/libasn1common.a"
    nm /mayhem/asn1c-fuzz > /tmp/asn1c-fuzz.nm 2>/dev/null || true
  fi
  grep -q __asan_default_options /tmp/asn1c-fuzz.nm || {
    echo "build.sh: ERROR — failed to bake __asan_default_options into asn1c-fuzz" >&2; exit 1; }
  echo "build.sh: baked __asan_default_options(detect_leaks=0) into /mayhem/asn1c-fuzz"
fi
