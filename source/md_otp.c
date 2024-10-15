#include <stdio.h>

#include "md_otp.h"

krb5_error_code
kdcpreauth_libOTP_initvt(krb5_context ctx, int maj_ver, int min_ver, 
                      krb5_plugin_vtable vtable);

static krb5_preauthtype otp_pa_type_list[] =
  { KRB5_PADATA_OTP_REQUEST, 0 };

// krb5_error_code 
// print_msg_from_kdc(krb5_context context, int maj_ver)
// {
//     /* General plugin concepts point 1*/
//     if(maj_ver != 1){
//         printf("maj_ver  != 1 s\n");
//         const char * msg = krb5_get_error_message(context, KRB5_PLUGIN_VER_NOTSUPP);
//         printf("%s\n", msg);
//         return KRB5_PLUGIN_VER_NOTSUPP;
//     }

// }


krb5_error_code
kdcpreauth_libOTP_initvt(krb5_context ctx, int maj_ver, int min_ver, 
                      krb5_plugin_vtable vtable)
{
    /* MUST */
     /* General plugin concepts point 2*/
    krb5_kdcpreauth_vtable vt; // структура интерфейса плагина 

    /* General plugin concepts point 1*/
    if(maj_ver != 1){
        // char * msg = krb5_get_error_message(ctx, KRB5_PLUGIN_VER_NOTSUPP);
        // printf("%s", msg);
        return KRB5_PLUGIN_VER_NOTSUPP;
    }

    /* General plugin concepts point 2*/
    /*
    General plugin concepts point 3
    Fill in the structure fields with pointers to method functions and static data, stopping at the field indicated by the supplied minor version. 
    Fields for unimplemented optional methods can be left alone; 
    it is not necessary to initialize them to NULL.
    */
    vt = (krb5_kdcpreauth_vtable)vtable;
    // Mandatory
    vt->name = "md_otp"; // shoud be literal NAME of Module
    // Mandatory
    vt->pa_type_list = otp_pa_type_list; // RFS 6560 4.2
    /* OPTIONAL */
    /* Optional: preauth plugin initialization function. */
    vt->init = otp_init;
    /* Optional: preauth plugin cleanup function. */
    vt->fini = otp_fini;
    /*
    * Optional: return the flags which the KDC should use for this module.  This
    * is a callback instead of a static value because the module may or may not
    * wish to count itself as a hardware preauthentication module (in other words,
    * the flags may be affected by the configuration, for example if a site
    * administrator can force a particular preauthentication type to be supported
    * using only hardware).  This function is called for each entry entry in the
    * server_pa_type_list.
    * 
    * верните флаги, которые KDC должен использовать для этого модуля.  Это
        обратный вызов, а не статическое значение, поскольку модуль может захотеть или не
        захотеть считать себя аппаратным модулем предварительной аутентификации (другими словами,
        на флаги может повлиять конфигурация, например, если
        администратор сайта может принудительно поддерживать определенный тип предварительной аутентификации
        , используя только аппаратное обеспечение).  Эта функция вызывается для каждой записи в списке
        server_pa_type_list.
    */
    vt->flags = otp_flags;
    /*
    * Optional: provide pa_data to send to the client as part of the "you need to
    * use preauthentication" error.  The implementation must invoke the respond
    * when complete, whether successful or not, either before returning or
    * asynchronously using the verto context returned by cb->event_context().
    *
    * This function is not allowed to create a modreq object because we have no
    * guarantee that the client will ever make a follow-up request, or that it
    * will hit this KDC if it does.
    * 
    * Необязательно: укажите pa_data для отправки клиенту как часть ошибки "вам необходимо
        использовать предварительную аутентификацию".  
        Реализация должна вызывать response по завершении, независимо от того, успешно это или нет, либо перед возвратом, либо асинхронно, используя контекст verto, возвращаемый cb->event_context(). 
        Этой функции не разрешено создавать объект modreq, поскольку у нас нет гарантии, что клиент когда-либо отправит повторный запрос или что он попадет в этот KDC, если это произойдет.
    */
    vt->edata = otp_edata;
    /*
    * Optional: verify preauthentication data sent by the client, setting the
    * TKT_FLG_PRE_AUTH or TKT_FLG_HW_AUTH flag in the enc_tkt_reply's "flags"
    * field as appropriate.  The implementation must invoke the respond function
    * when complete, whether successful or not, either before returning or
    * asynchronously using the verto context returned by cb->event_context().
    * 
    * Необязательно: проверьте данные предварительной аутентификации, отправленные клиентом, установив флажок TKT_FL_PRE_AUTH или TEXT_FLG_HW_AUTH в поле "флаги" enc_tkt_reply, если это необходимо.  
    * Реализация должна вызывать функцию response по завершении, независимо от того, успешно это или нет, либо перед возвратом, либо асинхронно, используя контекст verto, возвращаемый cb->event_context().
    */
    vt->verify = otp_verify;
    // The value 0 indicates success;
    // any other values are com_err codes.  
    // Use  to obtain a
    // string describing the error.

    com_err("MD_OTP", 0 , "LOADED");
    return 0;
}