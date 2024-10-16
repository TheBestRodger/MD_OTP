#include "md_otp.h"
#include "unistd.h"

#include <stdio.h>

krb5_error_code
otp_init(krb5_context context, krb5_kdcpreauth_moddata *moddata_out,
         const char **realmnames)
{
    char hostname[HOST_NAME_MAX + 1];
    krb5_error_code retval;
    krb5_data hndata;

    retval = gethostname(hostname, sizeof(hostname));
    
    if (retval != 0)
        return retval;

    com_err("otp_init_err",0,"Loaded INI func");
    printf("Inizialization of plugin, hostname = %s\n",hostname);


    
    return 0;
}

void
otp_fini(krb5_context context, krb5_kdcpreauth_moddata moddata)
{
    printf("otp_fini\n");
    com_err("otp_fini_err",0,"Loaded fini");
}

int
otp_flags(krb5_context context, krb5_preauthtype pa_type)
{
    printf("Inizialization of flags \n");
    com_err("otp_flags",0,"Loaded FLAGS %d", PA_REPLACES_KEY);
    return PA_REPLACES_KEY;
}
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
static krb5_data
make_data(void *data, unsigned int len)
{
    krb5_data d;

    d.magic = KV5M_DATA;
    d.data = (char *) data;
    d.length = len;
    return d;
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
static krb5_error_code
nonce_generate(krb5_context ctx, unsigned int length, krb5_data *nonce_out)
{
    krb5_data nonce;
    krb5_error_code retval;
    krb5_timestamp now;

    retval = krb5_timeofday(ctx, &now);
    if (retval != 0)
        return retval;

    retval = alloc_data(&nonce, sizeof(now) + length);
    if (retval != 0)
        return retval;

    retval = krb5_c_random_make_octets(ctx, &nonce);
    if (retval != 0) {
        free(nonce.data);
        return retval;
    }

    store_32_be(now, nonce.data);
    *nonce_out = nonce;
    return 0;
}
static void *
k5calloc(size_t nmemb, size_t size, krb5_error_code *code)
{
    void *ptr;

    /* Allocate at least one byte since zero-byte allocs may return NULL. */
    ptr = calloc(nmemb ? nmemb : 1, size ? size : 1);
    *code = (ptr == NULL) ? ENOMEM : 0;
    return ptr;
}
void
otp_edata(krb5_context context, krb5_kdc_req *request,
          krb5_kdcpreauth_callbacks cb, krb5_kdcpreauth_rock rock,
          krb5_kdcpreauth_moddata moddata, krb5_preauthtype pa_type,
          krb5_kdcpreauth_edata_respond_fn respond, void *arg)
{
    printf("otp_edata\n");
    com_err("otp_edata",0,"Loaded1");

    krb5_otp_tokeninfo ti, *tis[2] = { &ti, NULL };
    krb5_keyblock *armor_key = NULL;
    //krb5_pa_otp_challenge chl;
    krb5_pa_data *pa = NULL;
    krb5_error_code retval;
    krb5_data *encoding, nonce = make_data(NULL, 0);
    char *config;

    /* Determine if otp is enabled for the user. */
    // Retrieve a string attribute from the client DB entry, or NULL if no such
    // attribute is set. Free the result with the free_string callback.
    retval = cb->get_string(context, rock, "otp", &config);
    if (retval == 0 && config == NULL)
    {
        retval = ENOENT;
        com_err("otp_edata",0,"retval == 0 && config == NULL");
        goto out;
    }
    cb->free_string(context, rock, config);

    // Get a pointer to the FAST armor key, or NULL if the request did not use
    // FAST. The returned pointer is an alias and should not be freed.
    armor_key = cb->fast_armor(context, rock);
    if (armor_key == NULL) {
        retval = ENOENT;
        com_err("otp_edata",0,"armor_key == NULL");
        goto out;
    }

    /* Generate the nonce. */
    //retval = nonce_generate(context, armor_key->length, &nonce);
    // if (retval != 0)
    //     goto out;
    //chl.nonce = nonce;
    pa = k5calloc(1, sizeof(krb5_pa_data), &retval);
    if (pa == NULL) {
        krb5_free_data(context, encoding);
        com_err("otp_edata",0,"pa == NULL");
        goto out;
    }
    pa->pa_type = KRB5_PADATA_OTP_CHALLENGE;
    pa->contents = (krb5_octet *)encoding->data;
    pa->length = encoding->length;
out:
    com_err("WTF",0,"MESSAGEW = %d", retval);
    krb5_free_data_contents(context, &nonce);
    (*respond)(arg, retval, pa);

}

void
otp_verify(krb5_context context, krb5_data *req_pkt, krb5_kdc_req *request,
           krb5_enc_tkt_part *enc_tkt_reply, krb5_pa_data *pa,
           krb5_kdcpreauth_callbacks cb, krb5_kdcpreauth_rock rock,
           krb5_kdcpreauth_moddata moddata,
           krb5_kdcpreauth_verify_respond_fn respond, void *arg)
{
    printf("otp_verify\n");
    com_err("otp_verify",0,"Loaded2");
    return;
}