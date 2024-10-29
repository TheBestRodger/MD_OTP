#ifndef OTP_H_
#define OTP_H_

#include <krb5.h>
#include <krad.h>
#include "internal.h"
#include <krb5/clpreauth_plugin.h>
#include <krb5/kdcpreauth_plugin.h>
#include <mit-krb5/profile.h>

#define	ENOENT              2	/* No such file or directory */
#define	ENOMEM              12	/* Out of memory */
#define HOST_NAME_MAX		64/* Maximum host name length. */
#define DEFAULT_TYPE_NAME "DEFAULT"
#define DEFAULT_SOCKET_FMT KDC_RUN_DIR "/%s.socket"
#define DEFAULT_TIMEOUT 5
#define DEFAULT_RETRIES 3
#define MAX_SECRET_LEN 1024
#define KDC_DIR                 "/usr/local/var/krb5kdc"
#define KDC_RUN_DIR             "/usr/local/var/run/krb5kdc"
/* RFC 2865 */
#define OFFSET_CODE 0
#define OFFSET_ID 1
#define OFFSET_LENGTH 2
#define OFFSET_AUTH 4
#define OFFSET_ATTR 20
#define AUTH_FIELD_SIZE (OFFSET_ATTR - OFFSET_AUTH)


#define offset(d, o) (&(d)->data[o])
#define pkt_code_get(p) (*(krad_code *)offset(&(p)->pkt, OFFSET_CODE))
#define pkt_code_set(p, v) (*(krad_code *)offset(&(p)->pkt, OFFSET_CODE)) = v
#define pkt_id_get(p) (*(uchar *)offset(&(p)->pkt, OFFSET_ID))
#define pkt_id_set(p, v) (*(uchar *)offset(&(p)->pkt, OFFSET_ID)) = v
#define pkt_len_get(p)  load_16_be(offset(&(p)->pkt, OFFSET_LENGTH))
#define pkt_len_set(p, v)  store_16_be(v, offset(&(p)->pkt, OFFSET_LENGTH))
#define pkt_auth(p) ((uchar *)offset(&(p)->pkt, OFFSET_AUTH))
#define pkt_attr(p) ((unsigned char *)offset(&(p)->pkt, OFFSET_ATTR))

struct krad_packet_st {
    char buffer[KRAD_PACKET_SIZE_MAX];
    krad_attrset *attrset;
    krb5_data pkt;
};

typedef enum otp_response {
    otp_response_fail = 0,
    otp_response_success
    /* Other values reserved for responses like next token or new pin. */
} otp_response;


/* 
            General plugin concepts point 2

    Fill in the structure fields with pointers to method functions and static data, stopping at the field indicated by the supplied minor version. 
    Fields for unimplemented optional methods can be left alone; 
    it is not necessary to initialize them to NULL.

*/
    /* Optional: preauth plugin initialization function. */
krb5_error_code
otp_init(krb5_context context, krb5_kdcpreauth_moddata *moddata_out,
         const char **realmnames);
    /* Optional: preauth plugin cleanup function. */
void
otp_fini(krb5_context context, krb5_kdcpreauth_moddata moddata);
/*      Опционально:
        верните флаги, которые KDC должен использовать для этого модуля.  Это
        обратный вызов, а не статическое значение, поскольку модуль может захотеть или не
        захотеть считать себя аппаратным модулем предварительной аутентификации (другими словами,
        на флаги может повлиять конфигурация, например, если
        администратор сайта может принудительно поддерживать определенный тип предварительной аутентификации
        , используя только аппаратное обеспечение).  Эта функция вызывается для каждой записи в списке
        server_pa_type_list.
*/
int
otp_flags(krb5_context context, krb5_preauthtype pa_type);

/* Опционально: 
        укажите pa_data для отправки клиенту как часть ошибки "вам необходимо
        использовать предварительную аутентификацию".  
        Реализация должна вызывать response по завершении, независимо от того, успешно это или нет, либо перед возвратом, либо асинхронно, используя контекст verto, возвращаемый cb->event_context(). 
        Этой функции не разрешено создавать объект modreq, поскольку у нас нет гарантии, что клиент когда-либо отправит повторный запрос или что он попадет в этот KDC, если это произойдет.
*/
void
otp_edata(krb5_context context,
                              krb5_kdc_req *request,
                              krb5_kdcpreauth_callbacks cb,
                              krb5_kdcpreauth_rock rock,
                              krb5_kdcpreauth_moddata moddata,
                              krb5_preauthtype pa_type,
                              krb5_kdcpreauth_edata_respond_fn respond,
                              void *arg);
// krb5_error_code 
// otp_edata(krb5_context context, krb5_kdc_req *request,
//           krb5_kdcpreauth_callbacks cb, krb5_kdcpreauth_rock rock,
//           krb5_kdcpreauth_moddata moddata, krb5_preauthtype pa_type,
//           krb5_kdcpreauth_edata_respond_fn respond, void *arg);
/*  Опционально: 
        проверьте данные предварительной аутентификации, отправленные клиентом, установив флажок TKT_FL_PRE_AUTH или TEXT_FLG_HW_AUTH в поле "флаги" enc_tkt_reply, если это необходимо.  
        Реализация должна вызывать функцию response по завершении, независимо от того, успешно это или нет, либо перед возвратом, либо асинхронно, используя контекст verto, возвращаемый cb->event_context().
// */
// krb5_error_code otp_verify(krb5_context context,
//                                       krb5_data *req_pkt,
//                                       krb5_kdc_req *request,
//                                       krb5_enc_tkt_part *enc_tkt_reply,
//                                       krb5_pa_data *data,
//                                       void *gak_data);
void 
otp_verify(krb5_context context, krb5_data *req_pkt, krb5_kdc_req *request,
           krb5_enc_tkt_part *enc_tkt_reply, krb5_pa_data *pa,
           krb5_kdcpreauth_callbacks cb, krb5_kdcpreauth_rock rock,
           krb5_kdcpreauth_moddata moddata,
           krb5_kdcpreauth_verify_respond_fn respond, void *arg);


typedef void
(*otp_cb)(void *data, krb5_error_code retval, otp_response response,
          char *const *indicators);

typedef struct token_type_st {
    char *name;
    char *server;
    char *secret;
    int timeout;
    size_t retries;
    krb5_boolean strip_realm;
    char **indicators;
} token_type;

typedef struct otp_state_st 
{
    krb5_context ctx;
    krad_client *MF;
    token_type *types;
    krad_attrset *attrs;
} otp_state;

/* AlgorithmIdentifier */
typedef struct _krb5_algorithm_identifier {
    krb5_data algorithm;      /* OID */
    krb5_data parameters; /* Optional */
} krb5_algorithm_identifier;

typedef struct _krb5_otp_tokeninfo {
    krb5_flags flags;
    krb5_data vendor;
    krb5_data challenge;
    krb5_int32 length;          /* -1 for unspecified */
    krb5_int32 format;          /* -1 for unspecified */
    krb5_data token_id;
    krb5_data alg_id;
    krb5_algorithm_identifier **supported_hash_alg;
    krb5_int32 iteration_count; /* -1 for unspecified */
} krb5_otp_tokeninfo;

typedef struct _krb5_pa_otp_challenge {
    krb5_data nonce;
    krb5_data service;
    krb5_otp_tokeninfo **tokeninfo;
    krb5_data salt;
    krb5_data s2kparams;
} krb5_pa_otp_challenge;

typedef struct _krb5_pa_otp_req {
    krb5_int32 flags;
    krb5_data nonce;
    krb5_enc_data enc_data;
    krb5_algorithm_identifier *hash_alg;
    krb5_int32 iteration_count; /* -1 for unspecified */
    krb5_data otp_value;
    krb5_data pin;
    krb5_data challenge;
    krb5_timestamp time;
    krb5_data counter;
    krb5_int32 format;          /* -1 for unspecified */
    krb5_data token_id;
    krb5_data alg_id;
    krb5_data vendor;
} krb5_pa_otp_req;

typedef struct _krb5_pa_enc_ts {
    krb5_timestamp      patimestamp;
    krb5_int32          pausec;
} krb5_pa_enc_ts;
/*UTILS*/

krb5_data
make_data(void *data, unsigned int len);
krb5_data
empty_data();
krb5_error_code
alloc_data(krb5_data *data, unsigned int len);
void *
k5calloc(size_t nmemb, size_t size, krb5_error_code *code);
void *
k5alloc(size_t size, krb5_error_code *code);
// krb5_error_code
// nonce_generate(krb5_context ctx, unsigned int length, krb5_data *nonce_out);
// void
// md_store_32_be (unsigned int val, void *vp);

krb5_error_code
encode_krb5_pa_otp_challenge(const krb5_pa_otp_challenge *, krb5_data **);

// krb5_error_code
// token_types_decode(profile_t profile, token_type **out);

krb5_error_code
otp_state_new(krb5_context ctx, otp_state **out);

void
otp_state_free(otp_state *self);
// krb5_error_code
// encode_krb5_pa_otp_req(const krb5_pa_otp_req *, krb5_data **);

// krb5_error_code
// encode_krb5_pa_otp_enc_req(const krb5_data *, krb5_data **);

#endif /* OTP_H_ */
