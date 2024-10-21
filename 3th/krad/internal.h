/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* lib/krad/internal.h - Internal declarations for libkrad */


#ifndef INTERNAL_H_
#define INTERNAL_H_

#include <krb5.h>
#include "krad.h"

#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>


#undef  EAI_ADDRFAMILY
#define EAI_ADDRFAMILY  1
#undef  EAI_AGAIN
#define EAI_AGAIN       2
#undef  EAI_BADFLAGS
#define EAI_BADFLAGS    3
#undef  EAI_FAIL
#define EAI_FAIL        4
#undef  EAI_FAMILY
#define EAI_FAMILY      5
#undef  EAI_MEMORY
#define EAI_MEMORY      6
#undef  EAI_NODATA
#define EAI_NODATA      7
#undef  EAI_NONAME
#define EAI_NONAME      8
#undef  EAI_SERVICE
#define EAI_SERVICE     9
#undef  EAI_SOCKTYPE
#define EAI_SOCKTYPE    10
#undef  EAI_SYSTEM
#define EAI_SYSTEM      11

#ifndef UCHAR_MAX
#define UCHAR_MAX 255
#endif

/* RFC 2865 */
#define MAX_ATTRSIZE (UCHAR_MAX - 2)
#define MAX_ATTRSETSIZE (KRAD_PACKET_SIZE_MAX - 20)

typedef struct krad_remote_st krad_remote;

/* Validate constraints of an attribute. */
krb5_error_code
kr_attr_valid(krad_attr type, const krb5_data *data);

/* Encode an attribute. */
krb5_error_code
kr_attr_encode(krb5_context ctx, const char *secret, const unsigned char *auth,
               krad_attr type, const krb5_data *in,
               unsigned char outbuf[MAX_ATTRSIZE], size_t *outlen);

/* Decode an attribute. */
krb5_error_code
kr_attr_decode(krb5_context ctx, const char *secret, const unsigned char *auth,
               krad_attr type, const krb5_data *in,
               unsigned char outbuf[MAX_ATTRSIZE], size_t *outlen);

/* Encode the attributes into the buffer. */
krb5_error_code
kr_attrset_encode(const krad_attrset *set, const char *secret,
                  const unsigned char *auth,
                  unsigned char outbuf[MAX_ATTRSETSIZE], size_t *outlen);

/* Decode attributes from a buffer. */
krb5_error_code
kr_attrset_decode(krb5_context ctx, const krb5_data *in, const char *secret,
                  const unsigned char *auth, krad_attrset **set);

/* Create a new remote object which manages a socket and the state of
 * outstanding requests. */
// krb5_error_code
// kr_remote_new(krb5_context kctx, verto_ctx *vctx, const struct addrinfo *info,
//               const char *secret, krad_remote **rr);

/* Free a remote object. */
void
kr_remote_free(krad_remote *rr);

/*
 * Send the packet to the remote. The cb will be called when a response is
 * received, the request times out, the request is canceled or an error occurs.
 *
 * The timeout parameter is the total timeout across all retries in
 * milliseconds.
 *
 * If the cb is called with a retval of ETIMEDOUT it indicates that the
 * allotted time has elapsed. However, in the case of a timeout, we continue to
 * listen for the packet until krad_remote_cancel() is called or a response is
 * received. This means that cb will always be called twice in the event of a
 * timeout. This permits you to pursue other remotes while still listening for
 * a response from the first one.
 */
krb5_error_code
kr_remote_send(krad_remote *rr, krad_code code, krad_attrset *attrs,
               krad_cb cb, void *data, int timeout, size_t retries,
               const krad_packet **pkt);

/* Remove packet from the queue of requests awaiting responses. */
void
kr_remote_cancel(krad_remote *rr, const krad_packet *pkt);

/* Cancel all requests awaiting responses. */
void
kr_remote_cancel_all(krad_remote *rr);

// /* Determine if this remote object refers to the remote resource identified
//  * by the addrinfo struct and the secret. */
// krb5_boolean
// kr_remote_equals(const krad_remote *rr, const struct addrinfo *info,
//                  const char *secret);

/* Adapted from lib/krb5/os/sendto_kdc.c. */
static inline krb5_error_code
gai_error_code(int err)
{
    switch (err) {
    case 0:
        return 0;
    case EAI_BADFLAGS:
    case EAI_FAMILY:
    case EAI_SOCKTYPE:
    case EAI_SERVICE:
#ifdef EAI_ADDRFAMILY
    case EAI_ADDRFAMILY:
#endif
        return EINVAL;
    case EAI_AGAIN:
        return EAGAIN;
    case EAI_MEMORY:
        return ENOMEM;
#if defined(EAI_NODATA) && EAI_NODATA != EAI_NONAME
    case EAI_NODATA:
#endif
    case EAI_NONAME:
        return EADDRNOTAVAIL;
#ifdef EAI_OVERFLOW
    case EAI_OVERFLOW:
        return EOVERFLOW;
#endif
#ifdef EAI_SYSTEM
    case EAI_SYSTEM:
        return errno;
#endif
    default:
        return EINVAL;
    }
}

#endif /* INTERNAL_H_ */
