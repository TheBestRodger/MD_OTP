#include <stdio.h>

#include "krb/otp_state.h"
/*
    krb5_pa_enc_ts *et = NULL;
    krb5_pa_otp_req *req

    krb5_otp_tokeninfo ti, *tis[2] = { &ti, NULL };
    krb5_pa_otp_challenge chl;
    empty_data();
*/
#include "asm-generic/errno-base.h"
#include <com_err.h>

#include <verto.h>
#include <krb5/clpreauth_plugin.h>
#include <krb5/kdcpreauth_plugin.h>
#include <krb5/preauth_plugin.h>
#include <krb5/ccselect_plugin.h>

//#include <krad.h>
#include <krb/k5-json.h>

static krb5_preauthtype otp_pa_type_list[] =
  { KRB5_PADATA_OTP_REQUEST, 0 };

struct request_state {
    krb5_context context;
    krb5_kdcpreauth_verify_respond_fn respond;
    void *arg;
    krb5_enc_tkt_part *enc_tkt_reply;
    krb5_kdcpreauth_callbacks preauth_cb;
    krb5_kdcpreauth_rock rock;
};


static krb5_error_code
decrypt_encdata(krb5_context context, krb5_keyblock *armor_key,
                krb5_pa_otp_req *req, krb5_data *out)
{
    krb5_error_code retval;
    krb5_data plaintext;

    if (req == NULL)
        return EINVAL;

    retval = alloc_data(&plaintext, req->enc_data.ciphertext.length);
    if (retval)
        return retval;

    retval = krb5_c_decrypt(context, armor_key, KRB5_KEYUSAGE_PA_OTP_REQUEST,
                            NULL, &req->enc_data, &plaintext);
    if (retval != 0) {
        com_err("otp", retval, "Unable to decrypt encData in PA-OTP-REQUEST");
        free(plaintext.data);
        return retval;
    }

    *out = plaintext;
    return 0;
}

static krb5_error_code
nonce_verify(krb5_context ctx, krb5_keyblock *armor_key,
             const krb5_data *nonce)
{
    krb5_error_code retval;
    krb5_timestamp ts;
    krb5_data *er = NULL;

    if (armor_key == NULL || nonce->data == NULL) {
        retval = EINVAL;
        goto out;
    }

    /* Decode the PA-OTP-ENC-REQUEST structure. */
    retval = decode_krb5_pa_otp_enc_req(nonce, &er);
    if (retval != 0)
        goto out;

    /* Make sure the nonce is exactly the same size as the one generated. */
    if (er->length != armor_key->length + sizeof(krb5_timestamp))
        goto out;

    /* Check to make sure the timestamp at the beginning is still valid. */
    ts = load_32_be(er->data);
    retval = krb5_check_clockskew(ctx, ts);

out:
    krb5_free_data(ctx, er);
    return retval;
}

static krb5_error_code
timestamp_verify(krb5_context ctx, const krb5_data *nonce)
{
    krb5_error_code retval = EINVAL;
    krb5_pa_enc_ts *et = NULL;

    if (nonce->data == NULL)
        goto out;

    /* Decode the PA-ENC-TS-ENC structure. */
    retval = decode_krb5_pa_enc_ts(nonce, &et);
    if (retval != 0)
        goto out;

    /* Check the clockskew. */
    retval = krb5_check_clockskew(ctx, et->patimestamp);

out:
    krb5_free_pa_enc_ts(ctx, et);
    return retval;
}

static krb5_error_code
nonce_generate(krb5_context ctx, unsigned int length, krb5_data *nonce_out)
{
    krb5_data nonce;
    krb5_error_code retval;
    krb5_timestamp now;

    retval = krb5_timeofday(ctx, &now);
    if (retval != 0)
        return retval;

    retval = alloc_data(&nonce, sizeof(now) + length);
    if (retval != 0)
        return retval;

    retval = krb5_c_random_make_octets(ctx, &nonce);
    if (retval != 0) {
        free(nonce.data);
        return retval;
    }

    store_32_be(now, nonce.data);
    *nonce_out = nonce;
    return 0;
}

static void
on_response(void *data, krb5_error_code retval, otp_response response,
            char *const *indicators)
{
    struct request_state rs = *(struct request_state *)data;
    krb5_context context = rs.context;
    krb5_keyblock *armor_key;
    char *const *ind;

    free(data);

    if (retval == 0 && response != otp_response_success)
        retval = KRB5_PREAUTH_FAILED;
    if (retval)
        goto done;

    rs.enc_tkt_reply->flags |= TKT_FLG_PRE_AUTH;
    armor_key = rs.preauth_cb->fast_armor(context, rs.rock);
    if (armor_key == NULL) {
        retval = ENOENT;
        goto done;
    }

    retval = rs.preauth_cb->replace_reply_key(context, rs.rock, armor_key,
                                              FALSE);
    if (retval)
        goto done;

    for (ind = indicators; ind != NULL && *ind != NULL; ind++) {
        retval = rs.preauth_cb->add_auth_indicator(context, rs.rock, *ind);
        if (retval)
            goto done;
    }

done:
    rs.respond(rs.arg, retval, NULL, NULL, NULL);
}

static krb5_error_code
otp_init(krb5_context context, krb5_kdcpreauth_moddata *moddata_out,
         const char **realmnames)
{
    krb5_error_code retval;
    otp_state *state;

    retval = otp_state_new(context, &state);
    if (retval)
        return retval;
    *moddata_out = (krb5_kdcpreauth_moddata)state;
    return 0;
}

static void
otp_fini(krb5_context context, krb5_kdcpreauth_moddata moddata)
{
    otp_state_free((otp_state *)moddata);
}

static int
otp_flags(krb5_context context, krb5_preauthtype pa_type)
{
    return PA_REPLACES_KEY;
}

static void
otp_edata(krb5_context context, krb5_kdc_req *request,
          krb5_kdcpreauth_callbacks cb, krb5_kdcpreauth_rock rock,
          krb5_kdcpreauth_moddata moddata, krb5_preauthtype pa_type,
          krb5_kdcpreauth_edata_respond_fn respond, void *arg)
{
    krb5_otp_tokeninfo ti, *tis[2] = { &ti, NULL };
    krb5_keyblock *armor_key = NULL;
    krb5_pa_otp_challenge chl;
    krb5_pa_data *pa = NULL;
    krb5_error_code retval;
    krb5_data *encoding, nonce = empty_data();
    char *config;

    /* Determine if otp is enabled for the user. */
    retval = cb->get_string(context, rock, "otp", &config);
    if (retval == 0 && config == NULL)
        retval = ENOENT;
    if (retval != 0)
        goto out;
    cb->free_string(context, rock, config);

    /* Get the armor key.  This indicates the length of random data to use in
     * the nonce. */
    armor_key = cb->fast_armor(context, rock);
    if (armor_key == NULL) {
        retval = ENOENT;
        goto out;
    }

    /* Build the (mostly empty) challenge. */
    memset(&ti, 0, sizeof(ti));
    memset(&chl, 0, sizeof(chl));
    chl.tokeninfo = tis;
    ti.format = -1;
    ti.length = -1;
    ti.iteration_count = -1;

    /* Generate the nonce. */
    retval = nonce_generate(context, armor_key->length, &nonce);
    if (retval != 0)
        goto out;
    chl.nonce = nonce;

    /* Build the output pa-data. */
    retval = encode_krb5_pa_otp_challenge(&chl, &encoding);
    if (retval != 0)
        goto out;
    pa = k5alloc(sizeof(krb5_pa_data), &retval);
    if (pa == NULL) {
        krb5_free_data(context, encoding);
        goto out;
    }
    pa->pa_type = KRB5_PADATA_OTP_CHALLENGE;
    pa->contents = (krb5_octet *)encoding->data;
    pa->length = encoding->length;
    free(encoding);

out:
    krb5_free_data_contents(context, &nonce);
    (*respond)(arg, retval, pa);
}

static void
otp_verify(krb5_context context, krb5_data *req_pkt, krb5_kdc_req *request,
           krb5_enc_tkt_part *enc_tkt_reply, krb5_pa_data *pa,
           krb5_kdcpreauth_callbacks cb, krb5_kdcpreauth_rock rock,
           krb5_kdcpreauth_moddata moddata,
           krb5_kdcpreauth_verify_respond_fn respond, void *arg)
{
    krb5_keyblock *armor_key = NULL;
    krb5_pa_otp_req *req = NULL;
    struct request_state *rs;
    krb5_error_code retval;
    krb5_data d, plaintext;
    char *config;

    /* Get the FAST armor key. */
    armor_key = cb->fast_armor(context, rock);
    if (armor_key == NULL) {
        retval = KRB5KDC_ERR_PREAUTH_FAILED;
        com_err("otp", retval, "No armor key found when verifying padata");
        goto error;
    }

    /* Decode the request. */
    d = make_data(pa->contents, pa->length);
    retval = decode_krb5_pa_otp_req(&d, &req);
    if (retval != 0) {
        com_err("otp", retval, "Unable to decode OTP request");
        goto error;
    }

    /* Decrypt the nonce from the request. */
    retval = decrypt_encdata(context, armor_key, req, &plaintext);
    if (retval != 0) {
        com_err("otp", retval, "Unable to decrypt nonce");
        goto error;
    }

    /* Verify the nonce or timestamp. */
    retval = nonce_verify(context, armor_key, &plaintext);
    if (retval != 0)
        retval = timestamp_verify(context, &plaintext);
    krb5_free_data_contents(context, &plaintext);
    if (retval != 0) {
        com_err("otp", retval, "Unable to verify nonce or timestamp");
        goto error;
    }

    /* Create the request state.  Save the response callback, and the
     * enc_tkt_reply pointer so we can set the TKT_FLG_PRE_AUTH flag later. */
    rs = k5alloc(sizeof(struct request_state), &retval);
    if (rs == NULL)
        goto error;
    rs->context = context;
    rs->arg = arg;
    rs->respond = respond;
    rs->enc_tkt_reply = enc_tkt_reply;
    rs->preauth_cb = cb;
    rs->rock = rock;

    /* Get the principal's OTP configuration string. */
    retval = cb->get_string(context, rock, "otp", &config);
    if (retval == 0 && config == NULL)
        retval = KRB5_PREAUTH_FAILED;
    if (retval != 0) {
        free(rs);
        goto error;
    }

    /* Send the request. */
    otp_state_verify((otp_state *)moddata, cb->event_context(context, rock),
                     cb->client_name(context, rock), config, req, on_response,
                     rs);
    cb->free_string(context, rock, config);

    k5_free_pa_otp_req(context, req);
    return;

error:
    k5_free_pa_otp_req(context, req);
    (*respond)(arg, retval, NULL, NULL, NULL);
}
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
    vt->pa_type_list = otp_pa_type_list;
    vt->init = otp_init;
    vt->fini = otp_fini;
    vt->flags = otp_flags;
    vt->edata = otp_edata;
    vt->verify = otp_verify;

    com_err("otp", 0, "Loaded");

    return 0;
}

// krb5_error_code
// md_preauth_otp_initvt(krb5_context ctx, int maj_ver, int min_ver, 
//                       krb5_plugin_vtable vtable)
// {
//     /* MUST */
//      /* General plugin concepts point 2*/
//     krb5_kdcpreauth_vtable vt; // структура интерфейса плагина 

//     /* General plugin concepts point 1*/
//     if(maj_ver != 1){
//         char * msg = krb5_get_error_message(ctx, KRB5_PLUGIN_VER_NOTSUPP);
//         printf("%s", msg);
//         return KRB5_PLUGIN_VER_NOTSUPP;
//     }

//     /* General plugin concepts point 2*/
//     /*
//     General plugin concepts point 3
//     Fill in the structure fields with pointers to method functions and static data, stopping at the field indicated by the supplied minor version. 
//     Fields for unimplemented optional methods can be left alone; 
//     it is not necessary to initialize them to NULL.
//     */
//     vt = (krb5_kdcpreauth_vtable)vtable;
//     vt->name = "md_otp"; // shoud be literal NAME of Module
//     vt->pa_type_list = otp_pa_type_list; // RFS 6560 4.2
//     /* OPTIONAL */
//     /* Optional: preauth plugin initialization function. */
//     vt->init = otp_init;
//     /* Optional: preauth plugin cleanup function. */
//     vt->fini = otp_fini;
//     /*
//     * Optional: return the flags which the KDC should use for this module.  This
//     * is a callback instead of a static value because the module may or may not
//     * wish to count itself as a hardware preauthentication module (in other words,
//     * the flags may be affected by the configuration, for example if a site
//     * administrator can force a particular preauthentication type to be supported
//     * using only hardware).  This function is called for each entry entry in the
//     * server_pa_type_list.
//     */
//     vt->flags = otp_flags;
//     /*
//     * Optional: provide pa_data to send to the client as part of the "you need to
//     * use preauthentication" error.  The implementation must invoke the respond
//     * when complete, whether successful or not, either before returning or
//     * asynchronously using the verto context returned by cb->event_context().
//     *
//     * This function is not allowed to create a modreq object because we have no
//     * guarantee that the client will ever make a follow-up request, or that it
//     * will hit this KDC if it does.
//     */
//     vt->edata = otp_edata;
//     /*
//     * Optional: verify preauthentication data sent by the client, setting the
//     * TKT_FLG_PRE_AUTH or TKT_FLG_HW_AUTH flag in the enc_tkt_reply's "flags"
//     * field as appropriate.  The implementation must invoke the respond function
//     * when complete, whether successful or not, either before returning or
//     * asynchronously using the verto context returned by cb->event_context().
//     */
//     vt->verify = otp_verify;
//     // The value 0 indicates success;
//     // any other values are com_err codes.  
//     // Use  to obtain a
//     // string describing the error.

//     com_err("MD_OTP", 0 , "LOADED");
//     return 0;
// }