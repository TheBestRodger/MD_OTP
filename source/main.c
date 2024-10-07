#include <stdio.h>

#include "com_err.h"

#include "krb5/clpreauth_plugin.h"
#include "krb5/kdcpreauth_plugin.h"

#include "krb5/ccselect_plugin.h"

krb5_error_code
kdcpreauth_otp_initvt(krb5_context context, int maj_ver, int min_ver,
                      krb5_plugin_vtable vtable);

krb5_error_code
kdcpreauth_otp_initvt(krb5_context context, int maj_ver, int min_ver,
                      krb5_plugin_vtable vtable)
{
    krb5_kdcpreauth_vtable vt;

    if (maj_ver != 1)
        return KRB5_PLUGIN_VER_NOTSUPP;

    vt = (krb5_kdcpreauth_vtable)vtable;
    vt->name = "otp";
    vt->pa_type_list = NULL;
    vt->init = NULL;
    vt->fini = NULL;
    vt->flags = NULL;
    vt->edata = NULL;
    vt->verify = NULL;

    com_err("otp", 0, "Loaded");

    return 0;
}


struct request_state {
    krb5_context context;
    krb5_kdcpreauth_verify_respond_fn respond;
    void *arg;
    krb5_enc_tkt_part *enc_tkt_reply;
    krb5_kdcpreauth_callbacks preauth_cb;
    krb5_kdcpreauth_rock rock;
};
int main ()
{
    printf("OTP plugin start\n");
    com_err("otp", 0, "Loaded");
    return 0;
}