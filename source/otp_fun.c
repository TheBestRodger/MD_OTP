#include "md_otp.h"
#include "unistd.h"

#include <stdio.h>
krb5_error_code
otp_init(krb5_context context, krb5_kdcpreauth_moddata *moddata_out,
         const char **realmnames)
{
    char hostname[64 + 1];
    krb5_error_code retval;
    krb5_data hndata;

    retval = gethostname(hostname, sizeof(hostname));
    if (retval != 0)
        printf("!= 0 %s\n", hostname);
    printf("== 0 %s\n", hostname);

    printf("Inizialization of plugin\n");
    com_err("otp_init_err",0,"Loaded INI func");
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

void
otp_edata(krb5_context context, krb5_kdc_req *request,
          krb5_kdcpreauth_callbacks cb, krb5_kdcpreauth_rock rock,
          krb5_kdcpreauth_moddata moddata, krb5_preauthtype pa_type,
          krb5_kdcpreauth_edata_respond_fn respond, void *arg)
{
    printf("otp_edata\n");
    com_err("otp_edata",0,"Loaded1");

    // krb5_otp_tokeninfo ti, *tis[2] = { &ti, NULL };
    // krb5_keyblock *armor_key = NULL;
    // krb5_pa_otp_challenge chl;
    // krb5_pa_data *pa = NULL;
    krb5_error_code retval;
    // krb5_data *encoding, nonce = empty_data();
    char *config;

    /* Determine if otp is enabled for the user. */
    retval = cb->get_string(context, rock, "otp", &config);
    if (retval == 0 && config == NULL)
        retval = ENOENT;

    cb->free_string(context, rock, config);

    com_err("WTF",0,"MESSAGEW = %d", retval);
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