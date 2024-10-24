#include "unistd.h"
#include "md_attrset.h"
#include <stdio.h>
#include <string.h>
#include <mit-krb5/profile.h>
#include "kdb.h"
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
void otp_state_free(otp_state *self);
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

    state = calloc(1, sizeof(otp_state));
    if (state == NULL)
        goto error;

    retval = gethostname(hostname, sizeof(hostname));
    if (retval != 0)
        goto error;


    printf("Inizialization of plugin, hostname = %s\n",hostname);

    print_realms(realmnames);


    retval = krb5_get_profile(context, &profile);
    if (retval != 0)
        goto error;

    //retval = token_types_decode(profile, &state->types);
    profile_abandon(profile);
    com_err("otp_init_err",0,"Loading profile");



    com_err("otp_init_err",0,"Loading krad_attrset_new");
    retval = md_krad_attrset_new(context, &state->attrs);
    if (retval != 0)
        goto error;

    com_err("otp_init_err",0,"Loading md_krad_attrset_add");    
    hndata = make_data(hostname, strlen(hostname));
    retval = md_krad_attrset_add(state->attrs,
                              krad_attr_name2num("NAS-Identifier"), &hndata);
    if (retval != 0)
        goto error;

    com_err("otp_init_err",0,"Loading md_krad_attrset_add_number");
    retval = md_krad_attrset_add_number(state->attrs,
                                     krad_attr_name2num("Service-Type"),
                                     KRAD_SERVICE_TYPE_AUTHENTICATE_ONLY);
    if (retval != 0)
        goto error;

    *moddata_out = (krb5_kdcpreauth_moddata)state;

    state->ctx = context;
    com_err("otp_init_err",0,"Loaded func done");
    return 0;

error:
    printf("ERROR_KRB %d", retval);
    otp_state_free(state);
    return retval;
}
void
otp_state_free(otp_state *self)
{
    if (self == NULL)
        return;

    free(self);
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
    com_err("otp_flags",0,"Loaded FLAGS %d", PA_SUFFICIENT);//PA_REPLACES_KEY PA_SUFFICIENT
    return PA_SUFFICIENT;
}
static inline krb5_data
empty_data()
{
    return make_data(NULL, 0);
}
krb5_error_code
krb5_dbe_lookup_tl_data(krb5_context context, krb5_db_entry *entry,
                        krb5_tl_data *ret_tl_data)
{
    krb5_tl_data *tl_data;

    for (tl_data = entry->tl_data; tl_data; tl_data = tl_data->tl_data_next) {
        if (tl_data->tl_data_type == ret_tl_data->tl_data_type) {
            *ret_tl_data = *tl_data;
            return (0);
        }
    }

    /*
     * If the requested record isn't found, return zero bytes.  If it
     * ever means something to have a zero-length tl_data, this code
     * and its callers will have to be changed.
     */

    ret_tl_data->tl_data_length = 0;
    ret_tl_data->tl_data_contents = NULL;
    return (0);
}
/*
 * Prepare to iterate over the string attributes of entry.  The returned
 * pointers are aliases into entry's tl_data (or into an empty string literal)
 * and remain valid until the entry's tl_data is changed.
 */
static krb5_error_code
begin_attrs(krb5_context context, krb5_db_entry *entry, const char **pos_out,
            const char **end_out)
{
    krb5_error_code code;
    krb5_tl_data tl_data;

    *pos_out = *end_out = NULL;
    tl_data.tl_data_type = KRB5_TL_STRING_ATTRS;
    code = krb5_dbe_lookup_tl_data(context, entry, &tl_data);
    if (code)
        return code;

    /* Copy the current mapping to buf, updating key with value if found. */
    *pos_out = (const char *)tl_data.tl_data_contents;
    *end_out = *pos_out + tl_data.tl_data_length;
    return 0;
}

/* Find the next key and value pair in *pos and update *pos. */
static krb5_boolean
next_attr(const char **pos, const char *end, const char **key_out,
          const char **val_out)
{
    const char *key, *key_end, *val, *val_end;

    *key_out = *val_out = NULL;
    if (*pos == end)
        return FALSE;
    key = *pos;
    key_end = memchr(key, '\0', end - key);
    if (key_end == NULL)        /* Malformed representation; give up. */
        return FALSE;
    val = key_end + 1;
    val_end = memchr(val, '\0', end - val);
    if (val_end == NULL)        /* Malformed representation; give up. */
        return FALSE;

    *key_out = key;
    *val_out = val;
    *pos = val_end + 1;
    return TRUE;
}
krb5_error_code
krb5_dbe_get_string(krb5_context context, krb5_db_entry *entry,
                    const char *key, char **value_out)
{
    krb5_error_code code;
    const char *pos, *end, *mapkey, *mapval;

    *value_out = NULL;
    code = begin_attrs(context, entry, &pos, &end);
    if (code)
        return code;
    while (next_attr(&pos, end, &mapkey, &mapval)) {
        if (strcmp(mapkey, key) == 0) {
            *value_out = strdup(mapval);
            return (*value_out == NULL) ? ENOMEM : 0;
        }
    }

    return 0;
}

void
otp_edata(krb5_context context, krb5_kdc_req *request,
          krb5_kdcpreauth_callbacks cb, krb5_kdcpreauth_rock rock,
          krb5_kdcpreauth_moddata moddata, krb5_preauthtype pa_type,
          krb5_kdcpreauth_edata_respond_fn respond, void *arg)
{

    com_err("otp_edata",0,"Loading: otp_edata");
    krb5_otp_tokeninfo ti, *tis[2] = { &ti, NULL };
    krb5_keyblock *armor_key = NULL;
    krb5_pa_otp_challenge chl;
    krb5_pa_data *pa = NULL;
    krb5_error_code retval;
    krb5_data *encoding, nonce = empty_data();
    char *config;
    /*
    Определите, включен ли otp для пользователя. 
    Извлеките атрибут string из записи клиентской базы данных или значение NULL, если такой атрибут не задан. 
    Освободите результат с помощью обратного вызова free_string.
    */
    retval = cb->get_string(context, rock, "libOTP", &config);
    if (config == NULL)
        com_err("otp_edata",0,"config == NULL");
    if (retval != 0)
    {
        retval = ENOENT;
        com_err("otp_edata",0,"retval == 0");
        goto out;
    }
    //cb->free_string(context, rock, config);

    // Get a pointer to the FAST armor key, or NULL if the request did not use
    // FAST. The returned pointer is an alias and should not be freed.
    /*
        static krb5_keyblock *
    fast_armor(krb5_context context, krb5_kdcpreauth_rock rock)
    {
        return rock->rstate->armor_key;
    }
    */
    armor_key = cb->fast_armor(context, rock);

    if (armor_key == NULL) {
        retval = ENOENT;
        com_err("otp_edata",0,"armor_key == NULL");
        goto out;
    }    
    cb->free_string(context, rock, config);
    /* Build the (mostly empty) challenge. */
    com_err("otp_edata",0,"Loading: Build the (mostly empty) challenge");
    memset(&ti, 0, sizeof(ti));
    memset(&chl, 0, sizeof(chl));
    chl.tokeninfo = tis;
    ti.format = -1;
    ti.length = -1;
    ti.iteration_count = -1;

    /* Generate the nonce. */
    com_err("otp_edata",0,"Loading: Generate the nonce");
    retval = nonce_generate(context, armor_key->length, &nonce);
    if (retval != 0)
    {
        com_err("otp_edata",0,"nonce_generate == NULL");
        goto out;
    }
    chl.nonce = nonce;

    /* Build the output pa-data. */
    com_err("otp_edata",0,"Loading: Build the output pa-data");
    retval = encode_krb5_pa_otp_challenge(&chl, &encoding);
    if (retval != 0)
        goto out;
    com_err("otp_edata",0,"Loading: pa = k5calloc(1, sizeof(krb5_pa_data), &retval);");
    pa = k5calloc(1, sizeof(krb5_pa_data), &retval);
    if (pa == NULL) {
        krb5_free_data(context, encoding);
        com_err("otp_edata",0,"pa == NULL");
        goto out;
    }
    pa->pa_type = KRB5_PADATA_OTP_CHALLENGE;
    pa->contents = (krb5_octet *)encoding->data;
    pa->length = encoding->length;
    free(encoding);
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