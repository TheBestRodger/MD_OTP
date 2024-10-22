#include <internal.h>
/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* lib/krad/attrset.c - RADIUS attribute set functions for libkrad */


#include <k5-queue.h>
#include "internal.h"
#include <string.h>

//K5_TAILQ_HEAD(attr_head, attr_st);


// typedef struct attr_st attr;
// struct attr_st {
//     K5_TAILQ_ENTRY(attr_st) list;
//     krad_attr type;
//     krb5_data attr;
//     char buffer[MAX_ATTRSIZE];
// };
// struct krad_attrset_st {
//     krb5_context ctx;
//     struct attr_head list;
// };

krb5_error_code
md_krad_attrset_new(krb5_context ctx, krad_attrset **set);

void
md_krad_attrset_free(krad_attrset *set);

krb5_error_code
md_krad_attrset_add(krad_attrset *set, krad_attr type, const krb5_data *data);
krb5_error_code
md_krad_attrset_add_number(krad_attrset *set, krad_attr type, krb5_ui_4 num);
void
md_krad_attrset_del(krad_attrset *set, krad_attr type, size_t indx);
const krb5_data *
md_krad_attrset_get(const krad_attrset *set, krad_attr type, size_t indx);
krb5_error_code
md_krad_attrset_copy(const krad_attrset *set, krad_attrset **copy);

krb5_error_code
md_kr_attrset_encode(const krad_attrset *set, const char *secret,
                  const unsigned char *auth,
                  unsigned char outbuf[MAX_ATTRSETSIZE], size_t *outlen);
krb5_error_code
md_kr_attrset_decode(krb5_context ctx, const krb5_data *in, const char *secret,
                  const unsigned char *auth, krad_attrset **set_out);