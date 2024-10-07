/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* plugins/preauth/otp/otp_state.h - Internal declarations for OTP module */
#ifndef OTP_H_
#define OTP_H_

#include "krb5.h"
#include "k5-platform.h"
#include "krad.h"

/*
    krb5_pa_enc_ts *et = NULL;
    krb5_pa_otp_req *req

    krb5_otp_tokeninfo ti, *tis[2] = { &ti, NULL };
    krb5_pa_otp_challenge chl;
    empty_data();
    krb5_error_code
    krb5_context
    krb5_const_principal
*/

#include <verto.h>

#include <com_err.h>
#include <asm-generic/errno-base.h>
#include <profile.h>
#include <errno.h>

typedef unsigned char krad_code;
/* RFC 2865 */
#define OFFSET_CODE 0
#define OFFSET_ID 1
#define OFFSET_LENGTH 2
#define OFFSET_AUTH 4
#define OFFSET_ATTR 20
#define AUTH_FIELD_SIZE (OFFSET_ATTR - OFFSET_AUTH)

#define offset(d, o) (&(d)->data[o])
#define pkt_code_get(p) (*(krad_code *)offset(&(p)->pkt, OFFSET_CODE))
#define pkt_code_set(p, v) (*(krad_code *)offset(&(p)->pkt, OFFSET_CODE)) = v
#define pkt_id_get(p) (*(uchar *)offset(&(p)->pkt, OFFSET_ID))
#define pkt_id_set(p, v) (*(uchar *)offset(&(p)->pkt, OFFSET_ID)) = v
#define pkt_len_get(p)  load_16_be(offset(&(p)->pkt, OFFSET_LENGTH))
#define pkt_len_set(p, v)  store_16_be(v, offset(&(p)->pkt, OFFSET_LENGTH))
#define pkt_auth(p) ((uchar *)offset(&(p)->pkt, OFFSET_AUTH))
#define pkt_attr(p) ((unsigned char *)offset(&(p)->pkt, OFFSET_ATTR))

struct krad_packet_st {
    char buffer[KRAD_PACKET_SIZE_MAX];
    krad_attrset *attrset;
    krb5_data pkt;
};
typedef struct _krb5_pa_enc_ts {
    krb5_timestamp      patimestamp;
    krb5_int32          pausec;
} krb5_pa_enc_ts;

typedef struct _krb5_pa_for_user {
    krb5_principal      user;
    krb5_checksum       cksum;
    krb5_data           auth_package;
} krb5_pa_for_user;

typedef struct _krb5_s4u_userid {
    krb5_int32          nonce;
    krb5_principal      user;
    krb5_data           subject_cert;
    krb5_flags          options;
} krb5_s4u_userid;
/* AlgorithmIdentifier */
typedef struct _krb5_algorithm_identifier {
    krb5_data algorithm;      /* OID */
    krb5_data parameters; /* Optional */
} krb5_algorithm_identifier;
typedef struct _krb5_otp_tokeninfo {
    krb5_flags flags;
    krb5_data vendor;
    krb5_data challenge;
    krb5_int32 length;          /* -1 for unspecified */
    krb5_int32 format;          /* -1 for unspecified */
    krb5_data token_id;
    krb5_data alg_id;
    krb5_algorithm_identifier **supported_hash_alg;
    krb5_int32 iteration_count; /* -1 for unspecified */
} krb5_otp_tokeninfo;
typedef struct _krb5_pa_otp_challenge {
    krb5_data nonce;
    krb5_data service;
    krb5_otp_tokeninfo **tokeninfo;
    krb5_data salt;
    krb5_data s2kparams;
} krb5_pa_otp_challenge;


typedef enum otp_response {
    otp_response_fail = 0,
    otp_response_success
    /* Other values reserved for responses like next token or new pin. */
} otp_response;

typedef struct otp_state_st otp_state;
typedef void
(*otp_cb)(void *data, krb5_error_code retval, otp_response response,
          char *const *indicators);

typedef struct _krb5_pa_otp_req {
    krb5_int32 flags;
    krb5_data nonce;
    krb5_enc_data enc_data;
    krb5_algorithm_identifier *hash_alg;
    krb5_int32 iteration_count; /* -1 for unspecified */
    krb5_data otp_value;
    krb5_data pin;
    krb5_data challenge;
    krb5_timestamp time;
    krb5_data counter;
    krb5_int32 format;          /* -1 for unspecified */
    krb5_data token_id;
    krb5_data alg_id;
    krb5_data vendor;
} krb5_pa_otp_req;

krb5_error_code
otp_state_new(krb5_context ctx, otp_state **self);

void
otp_state_free(otp_state *self);

void
otp_state_verify(otp_state *state, verto_ctx *ctx, krb5_const_principal princ,
                 const char *config, const krb5_pa_otp_req *request,
                 otp_cb cb, void *data);

static inline krb5_data
make_data(void *data, unsigned int len)
{
    krb5_data d;

    d.magic = KV5M_DATA;
    d.data = (char *) data;
    d.length = len;
    return d;
}

static inline krb5_data
empty_data()
{
    return make_data(NULL, 0);
}
static inline krb5_data
string2data(char *str)
{
    return make_data(str, strlen(str));
}

static inline krb5_error_code
alloc_data(krb5_data *data, unsigned int len)
{
    /* Allocate at least one byte since zero-byte allocs may return NULL. */
    char *ptr = (char *) calloc((len > 0) ? len : 1, 1);

    if (ptr == NULL)
        return ENOMEM;
    data->magic = KV5M_DATA;
    data->data = ptr;
    data->length = len;
    return 0;
}
static inline void *
k5calloc(size_t nmemb, size_t size, krb5_error_code *code)
{
    void *ptr;

    /* Allocate at least one byte since zero-byte allocs may return NULL. */
    ptr = calloc(nmemb ? nmemb : 1, size ? size : 1);
    *code = (ptr == NULL) ? ENOMEM : 0;
    return ptr;
}

static inline void *
k5alloc(size_t size, krb5_error_code *code)
{
    return k5calloc(1, size, code);
}
static inline void *
k5memdup0(const void *in, size_t len, krb5_error_code *code)
{
    void *ptr = k5alloc(len + 1, code);

    if (ptr != NULL && len > 0)
        memcpy(ptr, in, len);
    return ptr;
}

#endif /* OTP_H_ */
