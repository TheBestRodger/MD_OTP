/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */

/*
 * Declarations for kdcpreauth plugin module implementors.
 *
    Интерфейс kdcpreauth имеет единственную поддерживаемую основную версию, которая равна 1.
    Основная версия 1 имеет текущую второстепенную версию 2. 
    Модули kdcpreauth должны
    определять функцию с именем kdcpreauth_<имя модуля>_initvt, соответствующую
    сигнатуре:
 *
 *   krb5_error_code
 *   kdcpreauth_modname_initvt(krb5_context context, int maj_ver, int min_ver,
 *                             krb5_plugin_vtable vtable);
 *
 * The initvt function should:
 *
 * - Check that the supplied maj_ver number is supported by the module, or
 *   return KRB5_PLUGIN_VER_NOTSUPP if it is not.
 *
 * - Cast the vtable pointer as appropriate for the interface and maj_ver:
 *     kdcpreauth, maj_ver == 1: Cast to krb5_kdcpreauth_vtable
 *
 * - Initialize the methods of the vtable, stopping as appropriate for the
 *   supplied min_ver.  Optional methods may be left uninitialized.
 *
 * Memory for the vtable is allocated by the caller, not by the module.
 */

#ifndef KRB5_KDCPREAUTH_PLUGIN_H
#define KRB5_KDCPREAUTH_PLUGIN_H

#include <krb5/krb5.h>
#include <krb5/plugin.h>

/* kdcpreauth mechanism property flags */

/*
    Заставляет KDC включать этот механизм в список поддерживаемых типов preauth
    ,если пользовательская запись в базе данных помечает пользователя как требующего аппаратной проверки подлинности
 */
#define PA_HARDWARE     0x00000004

/*
    Заставляет KDC включать этот механизм в список поддерживаемых
    типов preauth, если пользовательская запись в базе данных помечает пользователя как требующего предварительной аутентификации,
    и завершает предварительную проверку подлинности, если мы не можем проверить данные клиента.  
    Обратная сторона PA_SUFFICIENT.
 */
#define PA_REQUIRED     0x00000008

/*
    Заставляет KDC включать этот механизм в список поддерживаемых
    типов preauth, если пользовательская запись в базе данных помечает пользователя как требующего предварительной аутентификации, и отмечать предварительную аутентификацию как успешную, если мы можем проверить
    данные клиента.  Обратная сторона PA_REQUIRED.
 */
#define PA_SUFFICIENT   0x00000010

/*
 Помечает этот механизм предварительной аутентификации как механизм, который изменяет ключ, используемый для шифрования ответа клиенту.  
 У модулей, имеющих этот флаг, server_return_fn вызывается раньше, чем у модулей, у которых этого нет, и передается, если ранее вызванный модуль изменил ключ шифрования.
 */
#define PA_REPLACES_KEY 0x00000020

/*
 * Not really a padata type, so don't include it in any list of preauth types
 * which gets sent over the wire. ))))))))))))))))))))))))0
 */
#define PA_PSEUDO       0x00000080

/*
 * Indicates that e_data in non-FAST errors should be encoded as typed data
 * instead of padata.
 */
#define PA_TYPED_E_DATA 0x00000100

/* Abstract type for a KDC callback data handle. */
typedef struct krb5_kdcpreauth_rock_st *krb5_kdcpreauth_rock;

/* Abstract type for module data and per-request module data. */
typedef struct krb5_kdcpreauth_moddata_st *krb5_kdcpreauth_moddata;
typedef struct krb5_kdcpreauth_modreq_st *krb5_kdcpreauth_modreq;

/* The verto context structure type (typedef is in verto.h; we want to avoid a
 * header dependency for the moment). */
struct verto_ctx;

/* Before using a callback after version 1, modules must check the vers
 * field of the callback structure. */
typedef struct krb5_kdcpreauth_callbacks_st {
    int vers;

    krb5_deltat (*max_time_skew)(krb5_context context,
                                 krb5_kdcpreauth_rock rock);

    /*
    Получаем массив структур krb5_keyblock, содержащий клиентские ключи, 
    соответствующие типам запросов, завершающийся записью с типом ключа = 0.
    Возвращает значение ENOENT, если для типов запросов недоступны ключи.  Освободите
    результирующий объект с помощью обратного вызова free_keys.
     */
    krb5_error_code (*client_keys)(krb5_context context,
                                   krb5_kdcpreauth_rock rock,
                                   krb5_keyblock **keys_out);

    /* Free the result of client_keys. */
    void (*free_keys)(krb5_context context, krb5_kdcpreauth_rock rock,
                      krb5_keyblock *keys);

    /*
    Получаем закодированное тело запроса, которое иногда требуется для проверки контрольных сумм.
    Для быстрого запроса это закодированное внутреннее тело запроса.  
    Возвращаемый указатель является псевдонимом и не должен освобождаться.
     */
    krb5_data *(*request_body)(krb5_context context,
                               krb5_kdcpreauth_rock rock);

    /*
    Получите указатель на ключ FAST armor или значение NULL, если в запросе не использовался FAST.  
    Возвращаемый указатель является псевдонимом и не должен освобождаться.
     */
    krb5_keyblock *(*fast_armor)(krb5_context context,
                                 krb5_kdcpreauth_rock rock);

    /* 
    Извлеките строковый атрибут из записи клиентской базы данных или значение NULL, если такой атрибут не задан.  
    Освободите результат с помощью обратного вызова free_string.
    */
      krb5_error_code (*get_string)(krb5_context context,
                                  krb5_kdcpreauth_rock rock, const char *key,
                                  char **value_out);

    /* Free the result of get_string. */
    void (*free_string)(krb5_context context, krb5_kdcpreauth_rock rock,
                        char *string);

    /* Get a pointer to the client DB entry (returned as a void pointer to
     * avoid a dependency on a libkdb5 type). */
    void *(*client_entry)(krb5_context context, krb5_kdcpreauth_rock rock);

    /* Get a pointer to the verto context which should be used by an
     * asynchronous edata or verify method. */
    struct verto_ctx *(*event_context)(krb5_context context,
                                       krb5_kdcpreauth_rock rock);

    /* End of version 1 kdcpreauth callbacks. */

    /* Return true if the client DB entry contains any keys matching the
     * request enctypes. */
    krb5_boolean (*have_client_keys)(krb5_context context,
                                     krb5_kdcpreauth_rock rock);

    /* End of version 2 kdcpreauth callbacks. */

    /*
    Получите текущий ключ ответа.  
    Изначально ключом ответа является расшифрованный долгосрочный ключ клиента, выбранный в соответствии со списком типов запросов, или значение NULL, если соответствующий ключ не найден.  
    Значение может быть изменено с помощью обратного вызова replace_reply_key или метода return_padata, изменяющего encryption_key.  
    Возвращаемый указатель является псевдонимом и не должен освобождаться.
     */
    const krb5_keyblock *(*client_keyblock)(krb5_context context,
                                            krb5_kdcpreauth_rock rock);

    /* 
    Укажите индикатор аутентификации в качестве повторных данных authdata.  
    Повторяющиеся индикаторы будут проигнорированы.
     */
    krb5_error_code (*add_auth_indicator)(krb5_context context,
                                          krb5_kdcpreauth_rock rock,
                                          const char *indicator);

    /*
    Считайте значение данных для pa_type из файла cookie запроса, помещая его в out.  
    Значение, помещенное туда, является псевдонимом и не должно быть освобождено. 
    Возвращает true, если было получено значение для pa_type, и false, если нет.
     */
    krb5_boolean (*get_cookie)(krb5_context context, krb5_kdcpreauth_rock rock,
                               krb5_preauthtype pa_type, krb5_data *out);

    /*
    Задайте значение данных для pa_type, которое будет отправлено в защищенном файле cookie в следующем ответе об ошибке.  
    Если pa_type уже присутствует, значение игнорируется. 
    Если механизм preauth использует разные типы preauth для запросов и ответов, используйте тип запроса.  
    Защищенные файлы cookie зашифрованы с помощью ключа, известного только Kdc, но могут быть заменены в течение короткого промежутка времени для запросов с использованием того же клиента-участника.
     */
    krb5_error_code (*set_cookie)(krb5_context context,
                                  krb5_kdcpreauth_rock rock,
                                  krb5_preauthtype pa_type,
                                  const krb5_data *data);

    /* End of version 3 kdcpreauth callbacks. */

    /*
    Возвращает значение true, если princ совпадает с принципалом, указанным в запросе, или с принципалом клиента (возможно, канонизированным). 
    Если prince не совпадает, попробуйте выполнить поиск prince в базе данных с разрешенными псевдонимами и сравните результат с принципалом клиента, вернув значение true, если оно совпадает. 
    В противном случае верните значение false.
     */
    krb5_boolean (*match_client)(krb5_context context,
                                 krb5_kdcpreauth_rock rock,
                                 krb5_principal princ);

    /*
    Получите псевдоним участника записи в клиентской базе данных (возможно, канонизированный).
     */
    krb5_principal (*client_name)(krb5_context context,
                                  krb5_kdcpreauth_rock rock);

    /* End of version 4 kdcpreauth callbacks. */

    /*
    Попросите KDC отправить маркер свежести в методе data, сопровождающий ошибку PREAUTH_REQUIRED или PREAUTH_FAILED, если клиент указал поддержку маркеров свежести.  
    Этот обратный вызов должен вызываться только из метода data.
     */
    void (*send_freshness_token)(krb5_context context,
                                 krb5_kdcpreauth_rock rock);

    /* Validate a freshness token sent by the client.  Return 0 on success,
     * KRB5KDC_ERR_PREAUTH_EXPIRED on error. */
    /*
    Проверьте отправленный клиентом токен обновления.  
    В случае успеха верните 0, в случае ошибки - * KRB5KDC_ERR_PREAUTH_EXPIRED.
    */
    krb5_error_code (*check_freshness_token)(krb5_context context,
                                             krb5_kdcpreauth_rock rock,
                                             const krb5_data *token);

    /* End of version 5 kdcpreauth callbacks. */

    /*
     * Replace the reply key with key.  If is_strengthen is true, key must be a
     * derivative of the client long-term key.  This callback may be invoked
     * from the verify or return_padata methods.  If it is invoked from the
     * verify method, the new key will appear as the encrypting_key input to
     * return_padata.
     */
    /*
    Замените ключ ответа на key.  Если значение is_strengthen равно true, ключ должен быть производным от долгосрочного ключа клиента.  
    Этот обратный вызов может быть вызван из методов verify или return_pa data.  
    Если он вызывается из метода verify, новый ключ будет отображаться в качестве входных данных encryption_key для return_pdata.
    */
    krb5_error_code (*replace_reply_key)(krb5_context context,
                                         krb5_kdcpreauth_rock rock,
                                         const krb5_keyblock *key,
                                         krb5_boolean is_strengthen);

    /* End of version 6 kdcpreauth callbacks. */

} *krb5_kdcpreauth_callbacks;

/* Optional: preauth plugin initialization function. */
typedef krb5_error_code
(*krb5_kdcpreauth_init_fn)(krb5_context context,
                           krb5_kdcpreauth_moddata *moddata_out,
                           const char **realmnames);

/* Optional: preauth plugin cleanup function. */
typedef void
(*krb5_kdcpreauth_fini_fn)(krb5_context context,
                           krb5_kdcpreauth_moddata moddata);

/*
 * Optional: return the flags which the KDC should use for this module.  This
 * is a callback instead of a static value because the module may or may not
 * wish to count itself as a hardware preauthentication module (in other words,
 * the flags may be affected by the configuration, for example if a site
 * administrator can force a particular preauthentication type to be supported
 * using only hardware).  This function is called for each entry entry in the
 * server_pa_type_list.
 */
typedef int
(*krb5_kdcpreauth_flags_fn)(krb5_context context, krb5_preauthtype pa_type);

/*
 * Responder for krb5_kdcpreauth_edata_fn.  If invoked with a non-zero code, pa
 * will be ignored and the padata type will not be included in the hint list.
 * If invoked with a zero code and a null pa value, the padata type will be
 * included in the list with an empty value.  If invoked with a zero code and a
 * non-null pa value, pa will be included in the hint list and will later be
 * freed by the KDC.
 */
typedef void
(*krb5_kdcpreauth_edata_respond_fn)(void *arg, krb5_error_code code,
                                    krb5_pa_data *pa);

/*
 * Optional: provide pa_data to send to the client as part of the "you need to
 * use preauthentication" error.  The implementation must invoke the respond
 * when complete, whether successful or not, either before returning or
 * asynchronously using the verto context returned by cb->event_context().
 *
 * This function is not allowed to create a modreq object because we have no
 * guarantee that the client will ever make a follow-up request, or that it
 * will hit this KDC if it does.
 */
typedef void
(*krb5_kdcpreauth_edata_fn)(krb5_context context, krb5_kdc_req *request,
                            krb5_kdcpreauth_callbacks cb,
                            krb5_kdcpreauth_rock rock,
                            krb5_kdcpreauth_moddata moddata,
                            krb5_preauthtype pa_type,
                            krb5_kdcpreauth_edata_respond_fn respond,
                            void *arg);

/*
 * Responder for krb5_kdcpreauth_verify_fn.  Invoke with the arg parameter
 * supplied to verify, the error code (0 for success), an optional module
 * request state object to be consumed by return_fn or free_modreq_fn, optional
 * e_data to be passed to the caller if code is nonzero, and optional
 * authorization data to be included in the ticket.  In non-FAST replies,
 * e_data will be encoded as typed-data if the module sets the PA_TYPED_E_DATA
 * flag, and as pa-data otherwise.  e_data and authz_data will be freed by the
 * KDC.
 */
typedef void
(*krb5_kdcpreauth_verify_respond_fn)(void *arg, krb5_error_code code,
                                     krb5_kdcpreauth_modreq modreq,
                                     krb5_pa_data **e_data,
                                     krb5_authdata **authz_data);

/*
 * Optional: verify preauthentication data sent by the client, setting the
 * TKT_FLG_PRE_AUTH or TKT_FLG_HW_AUTH flag in the enc_tkt_reply's "flags"
 * field as appropriate.  The implementation must invoke the respond function
 * when complete, whether successful or not, either before returning or
 * asynchronously using the verto context returned by cb->event_context().
 */
typedef void
(*krb5_kdcpreauth_verify_fn)(krb5_context context,
                             krb5_data *req_pkt, krb5_kdc_req *request,
                             krb5_enc_tkt_part *enc_tkt_reply,
                             krb5_pa_data *data,
                             krb5_kdcpreauth_callbacks cb,
                             krb5_kdcpreauth_rock rock,
                             krb5_kdcpreauth_moddata moddata,
                             krb5_kdcpreauth_verify_respond_fn respond,
                             void *arg);

/*
 * Optional: generate preauthentication response data to send to the client as
 * part of the AS-REP.  If it needs to override the key which is used to
 * encrypt the response, it can do so by modifying encrypting_key, but it is
 * preferrable to use the replace_reply_key callback.
 */
typedef krb5_error_code
(*krb5_kdcpreauth_return_fn)(krb5_context context,
                             krb5_pa_data *padata,
                             krb5_data *req_pkt,
                             krb5_kdc_req *request,
                             krb5_kdc_rep *reply,
                             krb5_keyblock *encrypting_key,
                             krb5_pa_data **send_pa_out,
                             krb5_kdcpreauth_callbacks cb,
                             krb5_kdcpreauth_rock rock,
                             krb5_kdcpreauth_moddata moddata,
                             krb5_kdcpreauth_modreq modreq);

/* Optional: free a per-request context. */
typedef void
(*krb5_kdcpreauth_free_modreq_fn)(krb5_context,
                                  krb5_kdcpreauth_moddata moddata,
                                  krb5_kdcpreauth_modreq modreq);

/* Optional: invoked after init_fn to provide the module with a pointer to the
 * verto main loop. */
typedef krb5_error_code
(*krb5_kdcpreauth_loop_fn)(krb5_context context,
                           krb5_kdcpreauth_moddata moddata,
                           struct verto_ctx *ctx);

typedef struct krb5_kdcpreauth_vtable_st {
    /* Mandatory: name of module. */
    const char *name;

    /* Mandatory: pointer to zero-terminated list of pa_types which this module
     * can provide services for. */
    krb5_preauthtype *pa_type_list;

    krb5_kdcpreauth_init_fn init;
    krb5_kdcpreauth_fini_fn fini;
    krb5_kdcpreauth_flags_fn flags;
    krb5_kdcpreauth_edata_fn edata;
    krb5_kdcpreauth_verify_fn verify;
    krb5_kdcpreauth_return_fn return_padata;
    krb5_kdcpreauth_free_modreq_fn free_modreq;
    /* Minor 1 ends here. */

    krb5_kdcpreauth_loop_fn loop;
    /* Minor 2 ends here. */
} *krb5_kdcpreauth_vtable;

#endif /* KRB5_KDCPREAUTH_PLUGIN_H */
