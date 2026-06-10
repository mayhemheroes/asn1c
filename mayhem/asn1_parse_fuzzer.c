/*
 * asn1_parse_fuzzer.c — libFuzzer harness for asn1c's ASN.1 grammar parser.
 *
 * The classic asn1c fuzz surface is the front end that turns ASN.1 *source text*
 * into a module tree: asn1p_parse_buffer() (libasn1parser). It is the lexer +
 * yacc grammar, fed arbitrary bytes here. A parse failure returns NULL (handled);
 * a successful parse returns a tree we immediately free. Memory-safety defects in
 * the lexer/parser (overreads, UAF, bad frees on malformed input) surface as ASan
 * crashes; the rest of UBSan stays halting (the build relaxes only the benign,
 * ubiquitous 128-bit `1 << 127` shift in ASN_INTEGER_MAX — see mayhem/build.sh).
 *
 * Per-iteration cleanup: asn1p_delete() frees the returned tree and
 * asn1p_lex_destroy() tears down the (f)lex buffer/global state so repeated
 * libFuzzer iterations don't accumulate lexer state.
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "asn1parser.h"

/*
 * asn1c is a short-lived compiler whose parser deliberately does not free every
 * allocation before exit, so LeakSanitizer would flag benign, end-of-run leaks as
 * "crashes" on essentially every input. Disable leak detection by default (ASan's
 * use-after-free / heap-overflow / etc. stay ON). Overridable via ASAN_OPTIONS.
 */
const char *__asan_default_options(void) { return "detect_leaks=0"; }

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	/* asn1p_parse_buffer takes a NUL-terminated C string; copy + terminate. */
	char *buf = (char *)malloc(size + 1);
	if(!buf) return 0;
	if(size) memcpy(buf, data, size);
	buf[size] = '\0';

	asn1p_t *tree =
	    asn1p_parse_buffer(buf, (int)size, "fuzz-input", 1, A1P_NOFLAGS);
	if(tree) asn1p_delete(tree);

	/* Reset the flex lexer's global buffer state between iterations. */
	asn1p_lex_destroy();

	free(buf);
	return 0;
}
