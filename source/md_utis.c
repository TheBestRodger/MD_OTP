#include "md_otp.h"
#include "k5-platform.h"
krb5_data
make_data(void *data, unsigned int len)
{
    krb5_data d;

    d.magic = KV5M_DATA;
    d.data = (char *) data;
    d.length = len;
    return d;
}
krb5_error_code
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
void *
k5calloc(size_t nmemb, size_t size, krb5_error_code *code)
{
    void *ptr;

    /* Allocate at least one byte since zero-byte allocs may return NULL. */
    ptr = calloc(nmemb ? nmemb : 1, size ? size : 1);
    *code = (ptr == NULL) ? ENOMEM : 0;
    return ptr;
}
void *
k5alloc(size_t size, krb5_error_code *code)
{
    return k5calloc(1, size, code);
}
// void
// md_store_32_be (unsigned int val, void *vp)
// {
//     unsigned char *p = (unsigned char *) vp;
// #if defined(__GNUC__) && defined(K5_BE) && !defined(__cplusplus)
//     PUT(32,p,val);
// #elif defined(__GNUC__) && defined(K5_LE) && defined(SWAP32) && !defined(__cplusplus)
//     PUTSWAPPED(32,p,val);
// #else
//     p[0] = (val >> 24) & 0xff;
//     p[1] = (val >> 16) & 0xff;
//     p[2] = (val >>  8) & 0xff;
//     p[3] = (val      ) & 0xff;
// #endif
// }
krb5_error_code
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