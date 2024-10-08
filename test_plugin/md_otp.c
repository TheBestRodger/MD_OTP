#include <krb5.h>
#include <stdio.h>
#include <krb5/kdcpreauth_plugin.h>
#include <krb5/clpreauth_plugin.h>


static krb5_preauthtype otp_pa_type_list[] =
  { KRB5_PADATA_OTP_REQUEST, 0 };

krb5_error_code kdcpreauth(void *ctx, void *rock,
                           krb5_kdcpreauth_callbacks cb,
                           krb5_kdcpreauth_rock pkr,
                           krb5_kdcpreauth_moddata moddata,
                           krb5_kdcpreauth_modreq modreq,
                           krb5_kdc_req *request,
                           krb5_data *req_pkt,
                           krb5_data *response,
                           krb5_pa_data ***out_padata,
                           krb5_data **enc_padata,
                           krb5_last_req_entry ***pa_hint,
                           krb5_keyblock *client_key,
                           krb5_boolean *typed_e_data,
                           krb5_pa_data ***pa_dented_e_data){

    printf("Успешная аутентификация для клиента: %s\n", request->client->data->data);
    return 0;
}

krb5_error_code kdcpreauth_server_initvt(krb5_context context,
                                         int maj_ver,
                                         int min_ver,
                                         krb5_plugin_vtable vtable){
        /* MUST */
     /* General plugin concepts point 2*/
    krb5_kdcpreauth_vtable vt = (krb5_kdcpreauth_vtable)vtable;// структура интерфейса плагина 

    /* General plugin concepts point 1*/
    if(maj_ver != 1){
        const char * msg = krb5_get_error_message(context, KRB5_PLUGIN_VER_NOTSUPP);
        printf("%s", msg);
        return KRB5_PLUGIN_VER_NOTSUPP;
    }

    vt->name = "auth_log_plugin";
    vt->pa_type_list = otp_pa_type_list; // RFS 6560 4.2
    vt->edata = NULL;
    vt->verify = kdcpreauth;
    vt->return_padata = NULL;
    vt->free_modreq = NULL;
    printf("U S P E X \n");
    return 0; // 0 done other err
}