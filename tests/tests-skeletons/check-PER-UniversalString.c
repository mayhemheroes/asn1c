#include <stdio.h>
#include <assert.h>
#include <sys/time.h>

#include <UniversalString.h>
#include <per_support.h>

static void
check_encode_failed(asn_TYPE_descriptor_t *td, const char *buf, size_t buflen) {
    uint8_t uper_output_buffer[32];
    UniversalString_t *st_in;

    st_in = OCTET_STRING_new_fromBuf(td, buf, buflen);
    assert(st_in);
    assert(st_in->size == buflen);
    asn_enc_rval_t enc =
        uper_encode_to_buffer(&asn_DEF_UniversalString, st_in,
                              uper_output_buffer, sizeof(uper_output_buffer));
    assert(enc.encoded == -1);

    ASN_STRUCT_FREE(*td, st_in);
}

static void
check_round_trip_OK(asn_TYPE_descriptor_t *td, const char *buf, size_t buflen) {
    uint8_t uper_output_buffer[32];
    UniversalString_t *st_in;
    UniversalString_t *st_out = 0;

    st_in = OCTET_STRING_new_fromBuf(td, buf, buflen);
    assert(st_in);
    assert(st_in->size == buflen);

    asn_enc_rval_t enc =
        uper_encode_to_buffer(&asn_DEF_UniversalString, st_in,
                              uper_output_buffer, sizeof(uper_output_buffer));
    assert(enc.encoded > 0);

    asn_dec_rval_t dec =
        uper_decode(0, &asn_DEF_UniversalString, (void **)&st_out,
                    uper_output_buffer, (enc.encoded + 7) / 8, 0, 0);
    assert(dec.consumed == enc.encoded);
    assert(st_in->size == st_out->size);
    assert(memcmp(st_in->buf, st_out->buf, st_in->size) == 0);
    assert(st_out->size == buflen);
    assert(memcmp(st_out->buf, buf, buflen) == 0);

    ASN_STRUCT_FREE(*td, st_in);
    ASN_STRUCT_FREE(*td, st_out);
}

int
main() {
    static char UniversalString_data[] = { 0, 0, 0, 65, 0, 0, 0, 65 };

    check_round_trip_OK(&asn_DEF_UniversalString, UniversalString_data, 0);
    check_encode_failed(&asn_DEF_UniversalString, UniversalString_data, 1);
    check_encode_failed(&asn_DEF_UniversalString, UniversalString_data, 2);
    check_encode_failed(&asn_DEF_UniversalString, UniversalString_data, 3);
    check_round_trip_OK(&asn_DEF_UniversalString, UniversalString_data, 4);
    check_encode_failed(&asn_DEF_UniversalString, UniversalString_data, 5);
    check_encode_failed(&asn_DEF_UniversalString, UniversalString_data, 6);
    check_encode_failed(&asn_DEF_UniversalString, UniversalString_data, 7);
    check_round_trip_OK(&asn_DEF_UniversalString, UniversalString_data, 8);

	return 0;
}
