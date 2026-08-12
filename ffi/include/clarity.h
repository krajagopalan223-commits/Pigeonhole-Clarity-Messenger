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
typedef struct RelayTransport ClarityRelayTransport;
typedef struct MeshNode ClarityMeshNode;

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

/* Session persistence (survive app restart; store SEALED / in secure storage) */
ClarityBuffer clarity_session_serialize(const ClaritySession *sess);
ClaritySession *clarity_session_deserialize(const uint8_t *ptr, size_t len);

/* Safety numbers */
char *clarity_safety_number(const uint8_t *id_a /* 32 */, const uint8_t *id_b /* 32 */);

/*
 * Sealed sender + rotating inboxes (metadata protection).
 * Relay mail is addressed to clarity_inbox_id(identity, epoch) — a mailbox
 * key that rotates every 24h — and wrapped by clarity_seal_envelope so the
 * transport sees neither sender nor a stable recipient identifier.
 */
uint64_t clarity_epoch_for_unix(uint64_t unix_seconds);
void clarity_inbox_id(const uint8_t *identity /* 32 */, uint64_t epoch,
                      uint8_t *out /* 32 */);
/* decode + signature-verify a bundle; extract owner identity keys. 0 ok, -1 fail */
int32_t clarity_bundle_identity_keys(const uint8_t *bundle_ptr, size_t bundle_len,
                                     uint8_t *out_identity_ed /* 32 */,
                                     uint8_t *out_identity_dh /* 32 */);
ClarityBuffer clarity_seal_envelope(const ClarityAccount *acct,
                                    const uint8_t *recipient_identity_dh /* 32 */,
                                    const uint8_t *payload, size_t payload_len);
/* NULL-ptr buffer on failure; sender keys are written only on success and the
 * claimed sender is authenticated by decrypting the returned inner payload */
ClarityBuffer clarity_open_envelope(const ClarityAccount *acct,
                                    const uint8_t *blob, size_t blob_len,
                                    uint8_t *out_sender_ed /* 32 */,
                                    uint8_t *out_sender_dh /* 32 */);

/*
 * Relay transport (direct or via Tor). All calls BLOCK — invoke from a
 * background thread/isolate. Multi-item results use the list encoding:
 *   [uint32 count]( [uint32 len][bytes] )*   (all little-endian)
 */
ClarityRelayTransport *clarity_relay_transport_direct(const char *url);
ClarityRelayTransport *clarity_relay_transport_tor(const char *url, const char *socks_addr);
void clarity_relay_transport_free(ClarityRelayTransport *t);
int32_t clarity_relay_publish_account(const ClarityRelayTransport *t, const ClarityAccount *acct);
/* bytes-based publish (no Account handle) for a worker isolate; one_time_json is
 * the output of clarity_account_one_time_publics */
int32_t clarity_relay_publish(const ClarityRelayTransport *t,
                              const uint8_t *bundle, size_t bundle_len,
                              const uint8_t *one_time_json, size_t one_time_len);
/* empty buffer (ptr!=NULL,len==0) => no bundle; NULL ptr => transport error */
ClarityBuffer clarity_relay_fetch_bundle(const ClarityRelayTransport *t, const uint8_t *identity /* 32 */);
int32_t clarity_relay_send(const ClarityRelayTransport *t, const uint8_t *recipient /* 32 */,
                           const uint8_t *msg, size_t msg_len);
ClarityBuffer clarity_relay_poll(const ClarityRelayTransport *t, const uint8_t *recipient /* 32 */);

/*
 * Bluetooth mesh node. The Rust side owns routing; the app owns the radio.
 * Results use the same list encoding as above.
 */
ClarityMeshNode *clarity_mesh_node_new(const uint8_t *me /* 32 */);
void clarity_mesh_node_free(ClarityMeshNode *node);
/* returns the frame bytes to broadcast now */
ClarityBuffer clarity_mesh_originate(ClarityMeshNode *node, const uint8_t *recipient /* 32 */,
                                     const uint8_t *payload, size_t payload_len);
int32_t clarity_mesh_ingest(ClarityMeshNode *node, const uint8_t *frame, size_t frame_len);
ClarityBuffer clarity_mesh_pending_broadcast(const ClarityMeshNode *node);
ClarityBuffer clarity_mesh_take_inbox(ClarityMeshNode *node);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* CLARITY_H */
