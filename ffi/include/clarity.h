/*
 * clarity.h — C ABI for clarity-core.
 *
 * This header is consumed by the Flutter app (via dart:ffi) and can be used
 * from any C-compatible language. It mirrors the `extern "C"` surface in
 * ffi/src/lib.rs. Keep the two in sync.
 *
 * Memory ownership:
 *   - Opaque handles (ClarityAccount*, ClaritySession*) come from the
 *     *_generate / *_initiate / *_respond / *_deserialize calls and MUST be
 *     released with the matching *_free call.
 *   - Every non-null ClarityBuffer MUST be released with clarity_buffer_free.
 *   - A ClarityBuffer whose `ptr` is NULL signals an error.
 *   - C strings MUST be released with clarity_string_free.
 */
#ifndef CLARITY_H
#define CLARITY_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ClarityAccount ClarityAccount;
typedef struct ClaritySession ClaritySession;

typedef struct ClarityBuffer {
  uint8_t *ptr; /* NULL on error */
  size_t len;
} ClarityBuffer;

/* Buffer / string lifetime */
void clarity_buffer_free(ClarityBuffer buf);
void clarity_string_free(char *s);

/* Account lifecycle */
ClarityAccount *clarity_account_generate(void);
void clarity_account_free(ClarityAccount *acct);
ClarityBuffer clarity_account_serialize(const ClarityAccount *acct);
ClarityAccount *clarity_account_deserialize(const uint8_t *ptr, size_t len);

/* Account accessors */
void clarity_account_identity_public(const ClarityAccount *acct, uint8_t *out /* 32 bytes */);
ClarityBuffer clarity_account_bundle_base(const ClarityAccount *acct);
ClarityBuffer clarity_account_one_time_publics(const ClarityAccount *acct); /* JSON */

/* Sessions */
ClaritySession *clarity_session_initiate(const ClarityAccount *acct,
                                         const uint8_t *bundle_ptr,
                                         size_t bundle_len);
ClaritySession *clarity_session_respond(ClarityAccount *acct,
                                        const uint8_t *msg_ptr,
                                        size_t msg_len,
                                        ClarityBuffer *out_plaintext);
ClarityBuffer clarity_session_encrypt(ClaritySession *sess,
                                      const uint8_t *pt_ptr,
                                      size_t pt_len);
ClarityBuffer clarity_session_decrypt(ClaritySession *sess,
                                      const uint8_t *msg_ptr,
                                      size_t msg_len);
void clarity_session_free(ClaritySession *sess);

/* Safety numbers */
char *clarity_safety_number(const uint8_t *id_a /* 32 */, const uint8_t *id_b /* 32 */);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* CLARITY_H */
