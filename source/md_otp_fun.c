#include "md_otp.h"
#include "krad.h"
#include "unistd.h"
#include "md_attrset.h"
#include <stdio.h>
#include <string.h>
#include <mit-krb5/profile.h>

typedef struct otp_state_st 
{
    krb5_context ctx;
    krad_client *MF;
    token_type *types;
    krad_attrset *attrs;
} otp_state;


void print_realms(const char **realmnames)
{
    int i = 0;
    // Последний элемент массива - NULL, чтобы обозначить конец
    while (realmnames[i] != NULL)
    {
        printf("Realm name [%d] : %s\n", i, realmnames[i]);
        ++i;
    }
}
krb5_error_code
otp_init(krb5_context context, krb5_kdcpreauth_moddata *moddata_out,
         const char **realmnames)
{    
    com_err("otp_init_err",0,"Loading INI func");
    char hostname[HOST_NAME_MAX + 1];
    krb5_error_code retval;    
    otp_state *state;
    profile_t profile;
    krb5_data hndata;
    // krb5_data hndata;

    retval = gethostname(hostname, sizeof(hostname));
    
    if (retval != 0)
        return retval;


    printf("Inizialization of plugin, hostname = %s\n",hostname);

    print_realms(realmnames);


    retval = krb5_get_profile(context, &profile);
    if (retval != 0)
        printf("ERROR_KRB %d", retval);
    //retval = token_types_decode(profile, &state->types);
    profile_abandon(profile);
    com_err("otp_init_err",0,"Loading profile");
    hndata = make_data(hostname, strlen(hostname));

    com_err("otp_init_err",0,"Loading krad_attrset_new");

    retval = md_krad_attrset_new(context, &state->attrs);

    if (retval != 0)
        printf("ERROR_KRB %d", retval);

    retval = md_krad_attrset_add(state->attrs,
                              krad_attr_name2num("NAS-Identifier"), &hndata);
    if (retval != 0)
        printf("ERROR_KRB %d", retval);

    retval = md_krad_attrset_add_number(state->attrs,
                                     krad_attr_name2num("Service-Type"),
                                     KRAD_SERVICE_TYPE_AUTHENTICATE_ONLY);
    if (retval != 0)
        printf("ERROR_KRB %d", retval);

    *moddata_out = (krb5_kdcpreauth_moddata)state;

    com_err("otp_init_err",0,"Loaded func done");
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
    com_err("otp_flags",0,"Loaded FLAGS %d", PA_REQUIRED);//PA_REPLACES_KEY
    return PA_REQUIRED;
}

void
otp_edata(krb5_context context, krb5_kdc_req *request,
          krb5_kdcpreauth_callbacks cb, krb5_kdcpreauth_rock rock,
          krb5_kdcpreauth_moddata moddata, krb5_preauthtype pa_type,
          krb5_kdcpreauth_edata_respond_fn respond, void *arg)
{
    com_err("otp_edata",0,"Loading: otp_edata");
    // com_err("otp_edata",0,"Wait for 15");
    // sleep(15);
    // com_err("otp_edata",0,"end of 15");
    krb5_otp_tokeninfo ti, *tis[2] = { &ti, NULL };
    krb5_keyblock *armor_key = NULL;
    //krb5_pa_otp_challenge chl;
    //Слово «padata» используется как сокращение от «данные предварительной аутентификации».
    krb5_pa_data *pa = NULL;
    krb5_error_code retval;
    krb5_data *encoding, nonce = make_data(NULL, 0);
    char *config;
    pa = k5calloc(1, sizeof(krb5_pa_data), &retval);
    if (pa == NULL) {
        krb5_free_data(context, encoding);
        com_err("otp_edata",0,"pa == NULL");
        goto out;
    }
    pa->pa_type = KRB5_PADATA_OTP_CHALLENGE;
    pa->contents = (krb5_octet *)encoding->data;
    pa->length = encoding->length;
    /* Determine if otp is enabled for the user. */
    // Retrieve a string attribute from the client DB entry, or NULL if no such
    // attribute is set. Free the result with the free_string callback.
    /*
    Определите, включен ли otp для пользователя. 
    Извлеките атрибут string из записи клиентской базы данных или значение NULL, если такой атрибут не задан. 
    Освободите результат с помощью обратного вызова free_string.
    */
    retval = cb->get_string(context, rock, "libOTP", &config);
    if (config == NULL)
        com_err("otp_edata",0,"config == NULL");
    if (retval == 0)
    {
        retval = ENOENT;
        com_err("otp_edata",0,"retval == 0");
        goto out;
    }
    cb->free_string(context, rock, config);

    // Get a pointer to the FAST armor key, or NULL if the request did not use
    // FAST. The returned pointer is an alias and should not be freed.
    armor_key = cb->fast_armor(context, rock);
    if (armor_key == NULL) {
        retval = ENOENT;
        com_err("otp_edata",0,"armor_key == NULL");
        goto out;
    }

    /* Generate the nonce. */
    //retval = nonce_generate(context, armor_key->length, &nonce);
    // if (retval != 0)
    //     goto out;
    //chl.nonce = nonce;
    // pa = k5calloc(1, sizeof(krb5_pa_data), &retval);
    // if (pa == NULL) {
    //     krb5_free_data(context, encoding);
    //     com_err("otp_edata",0,"pa == NULL");
    //     goto out;
    // }
    // pa->pa_type = KRB5_PADATA_OTP_CHALLENGE;
    // pa->contents = (krb5_octet *)encoding->data;
    // pa->length = encoding->length;
out:
    com_err("MD_OUT",0,"MESSAGEW = %d", retval);
    krb5_free_data_contents(context, &nonce);
    (*respond)(arg, retval, pa);

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