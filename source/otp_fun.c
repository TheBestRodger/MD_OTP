#include "md_otp.h"

krb5_error_code
otp_init(krb5_context context, krb5_kdcpreauth_moddata *moddata_out,
         const char **realmnames)
{
    printf("otp_init");
    return 0;
}

void
otp_fini(krb5_context context, krb5_kdcpreauth_moddata moddata)
{
    printf("otp_fini");
    free(NULL);
}

int
otp_flags(krb5_context context, krb5_preauthtype pa_type)
{
    printf("otp_flags");
    return PA_REPLACES_KEY;
}

void
otp_edata(krb5_context context, krb5_kdc_req *request,
          krb5_kdcpreauth_callbacks cb, krb5_kdcpreauth_rock rock,
          krb5_kdcpreauth_moddata moddata, krb5_preauthtype pa_type,
          krb5_kdcpreauth_edata_respond_fn respond, void *arg)
{
   printf("otp_edata");
}

void
otp_verify(krb5_context context, krb5_data *req_pkt, krb5_kdc_req *request,
           krb5_enc_tkt_part *enc_tkt_reply, krb5_pa_data *pa,
           krb5_kdcpreauth_callbacks cb, krb5_kdcpreauth_rock rock,
           krb5_kdcpreauth_moddata moddata,
           krb5_kdcpreauth_verify_respond_fn respond, void *arg)
{
    printf("otp_verify");
    return;
}