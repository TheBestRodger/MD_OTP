#ifndef OTP_H_
#define OTP_H_

#include <krb5.h>

#include <krb5/clpreauth_plugin.h>
#include <krb5/kdcpreauth_plugin.h>

// krb5_error_code 
// print_msg_from_kdc(krb5_context context, int maj_ver);

#define	ENOENT		 2	/* No such file or directory */
krb5_error_code
otp_init(krb5_context context, krb5_kdcpreauth_moddata *moddata_out,
         const char **realmnames);

void
otp_fini(krb5_context context, krb5_kdcpreauth_moddata moddata);

int
otp_flags(krb5_context context, krb5_preauthtype pa_type);

void
otp_edata(krb5_context context, krb5_kdc_req *request,
          krb5_kdcpreauth_callbacks cb, krb5_kdcpreauth_rock rock,
          krb5_kdcpreauth_moddata moddata, krb5_preauthtype pa_type,
          krb5_kdcpreauth_edata_respond_fn respond, void *arg);

void
otp_verify(krb5_context context, krb5_data *req_pkt, krb5_kdc_req *request,
           krb5_enc_tkt_part *enc_tkt_reply, krb5_pa_data *pa,
           krb5_kdcpreauth_callbacks cb, krb5_kdcpreauth_rock rock,
           krb5_kdcpreauth_moddata moddata,
           krb5_kdcpreauth_verify_respond_fn respond, void *arg);




#endif /* OTP_H_ */
