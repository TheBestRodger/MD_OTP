/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* include/k5-base64.h - base64 declarations */
#ifndef K5_BASE64_H
#define K5_BASE64_H

#include <stddef.h>

/* base64-encode data and return it in an allocated buffer.  Return NULL if out
 * of memory. */
char *k5_base64_encode(const void *data, size_t len);

/*
 * Decode str as base64 and return the result in an allocated buffer, setting
 * *len_out to the length.  Return NULL and *len_out == 0 if out of memory,
 * NULL and *len_out == SIZE_MAX on invalid input.
 */
void *k5_base64_decode(const char *str, size_t *len_out);

#endif /* K5_BASE64_H */
