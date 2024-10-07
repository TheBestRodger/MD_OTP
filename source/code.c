/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* lib/krad/code.c - RADIUS code name table for libkrad */


//#include "internal.h"

#include <string.h>
#ifndef UCHAR_MAX
#define UCHAR_MAX 255
#endif
typedef unsigned char krad_code;
static const char *codes[UCHAR_MAX] = {
    "Access-Request",
    "Access-Accept",
    "Access-Reject",
    "Accounting-Request",
    "Accounting-Response",
    "Accounting-Status",
    "Password-Request",
    "Password-Ack",
    "Password-Reject",
    "Accounting-Message",
    "Access-Challenge",
    "Status-Server",
    "Status-Client",
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    "Resource-Free-Request",
    "Resource-Free-Response",
    "Resource-Query-Request",
    "Resource-Query-Response",
    "Alternate-Resource-Reclaim-Request",
    "NAS-Reboot-Request",
    "NAS-Reboot-Response",
    NULL,
    "Next-Passcode",
    "New-Pin",
    "Terminate-Session",
    "Password-Expired",
    "Event-Request",
    "Event-Response",
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    "Disconnect-Request",
    "Disconnect-Ack",
    "Disconnect-Nak",
    "Change-Filters-Request",
    "Change-Filters-Ack",
    "Change-Filters-Nak",
    NULL,
    NULL,
    NULL,
    NULL,
    "IP-Address-Allocate",
    "IP-Address-Release",
};

krad_code
krad_code_name2num(const char *name)
{
    unsigned char i;

    for (i = 0; i < UCHAR_MAX; i++) {
        if (codes[i] == NULL)
            continue;

        if (strcmp(codes[i], name) == 0)
            return ++i;
    }

    return 0;
}

const char *
krad_code_num2name(krad_code code)
{
    if (code == 0)
        return NULL;

    return codes[code - 1];
}
