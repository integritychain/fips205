#ifndef __FIPS205_H__
#define __FIPS205_H__
/*
  SLH-DSA C interface for the four 128-bit parameter sets.

  192-bit and 256-bit sets are Rust-only in this release.

  Memory allocation and tracking are entirely the job of the caller.
  The shared object has no internal state between calls.

  These functions return 0 (SLH_DSA_OK) on success, or a non-zero octet
  on error.

  slh_dsa_keygen_seed is sk_seed || sk_prf || pk_seed, 16 bytes each.
  A NULL keygen seed draws those three values from the OS RNG.

  slh_dsa_sign_seed is the 16-byte hedged opt_rand.
  hedged == 0 selects the deterministic variant (opt_rand = PK.seed) and
  ignores the sign seed. hedged != 0 with a NULL sign seed draws opt_rand
  from the OS RNG. hedged != 0 with a sign seed uses those 16 bytes, even
  when they are all zero.

  Random keygen and sign are static inline wrappers. They are not exported
  from libfips205.so.
*/
#include <stddef.h>
#include <stdint.h>

typedef uint8_t slh_dsa_err;

static const slh_dsa_err SLH_DSA_OK = 0;
static const slh_dsa_err SLH_DSA_NULL_PTR_ERROR = 1;
static const slh_dsa_err SLH_DSA_SERIALIZATION_ERROR = 2;
static const slh_dsa_err SLH_DSA_DESERIALIZATION_ERROR = 3;
static const slh_dsa_err SLH_DSA_KEYGEN_ERROR = 4;
static const slh_dsa_err SLH_DSA_SIGN_ERROR = 5;
static const slh_dsa_err SLH_DSA_VERIFICATION_ERROR = 6;
static const slh_dsa_err SLH_DSA_VERIFICATION_FAILURE = 7;

typedef struct slh_dsa_keygen_seed {
  uint8_t data[48];
} slh_dsa_keygen_seed;

typedef struct slh_dsa_sign_seed {
  uint8_t data[16];
} slh_dsa_sign_seed;

/* DER-encoded OIDs for hash_sign and hash_verify. Same bytes as fips205::pre_hash. */

static const uint8_t SLH_DSA_SHA2_224[] = { 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04 };
static const uint8_t SLH_DSA_SHA2_256[] = { 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01 };
static const uint8_t SLH_DSA_SHA2_384[] = { 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02 };
static const uint8_t SLH_DSA_SHA2_512[] = { 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03 };
static const uint8_t SLH_DSA_SHA2_512_224[] = { 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x05 };
static const uint8_t SLH_DSA_SHA2_512_256[] = { 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x06 };
static const uint8_t SLH_DSA_SHA3_224[] = { 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x07 };
static const uint8_t SLH_DSA_SHA3_256[] = { 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x08 };
static const uint8_t SLH_DSA_SHA3_384[] = { 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x09 };
static const uint8_t SLH_DSA_SHA3_512[] = { 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0a };
static const uint8_t SLH_DSA_SHAKE_128[] = { 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0b };
static const uint8_t SLH_DSA_SHAKE_256[] = { 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0c };

typedef struct slh_dsa_sha2_128s_private_key {
  uint8_t data[64];
} slh_dsa_sha2_128s_private_key;
typedef struct slh_dsa_sha2_128s_public_key {
  uint8_t data[32];
} slh_dsa_sha2_128s_public_key;
typedef struct slh_dsa_sha2_128s_signature {
  uint8_t data[7856];
} slh_dsa_sha2_128s_signature;

typedef struct slh_dsa_sha2_128f_private_key {
  uint8_t data[64];
} slh_dsa_sha2_128f_private_key;
typedef struct slh_dsa_sha2_128f_public_key {
  uint8_t data[32];
} slh_dsa_sha2_128f_public_key;
typedef struct slh_dsa_sha2_128f_signature {
  uint8_t data[17088];
} slh_dsa_sha2_128f_signature;

typedef struct slh_dsa_shake_128s_private_key {
  uint8_t data[64];
} slh_dsa_shake_128s_private_key;
typedef struct slh_dsa_shake_128s_public_key {
  uint8_t data[32];
} slh_dsa_shake_128s_public_key;
typedef struct slh_dsa_shake_128s_signature {
  uint8_t data[7856];
} slh_dsa_shake_128s_signature;

typedef struct slh_dsa_shake_128f_private_key {
  uint8_t data[64];
} slh_dsa_shake_128f_private_key;
typedef struct slh_dsa_shake_128f_public_key {
  uint8_t data[32];
} slh_dsa_shake_128f_public_key;
typedef struct slh_dsa_shake_128f_signature {
  uint8_t data[17088];
} slh_dsa_shake_128f_signature;

#ifdef  __cplusplus
extern "C" {
#endif

slh_dsa_err slh_dsa_populate_seed(slh_dsa_keygen_seed *seed_out);


/* slh_dsa_sha2_128s */
slh_dsa_err slh_dsa_sha2_128s_keygen_from_seed(const slh_dsa_keygen_seed *seed,
                                 slh_dsa_sha2_128s_public_key *public_out,
                                 slh_dsa_sha2_128s_private_key *private_out);

static inline slh_dsa_err slh_dsa_sha2_128s_keygen(slh_dsa_sha2_128s_public_key *public_out,
                                     slh_dsa_sha2_128s_private_key *private_out) {
  return slh_dsa_sha2_128s_keygen_from_seed(NULL, public_out, private_out);
}

slh_dsa_err slh_dsa_sha2_128s_get_public_key(const slh_dsa_sha2_128s_private_key *private_key,
                               slh_dsa_sha2_128s_public_key *public_out);

slh_dsa_err slh_dsa_sha2_128s_sign_with_seed(const slh_dsa_sha2_128s_private_key *private_key,
                               const uint8_t *message,
                               size_t message_size,
                               const uint8_t *context,
                               size_t context_size,
                               const slh_dsa_sign_seed *seed,
                               uint8_t hedged,
                               slh_dsa_sha2_128s_signature *signature_out);

static inline slh_dsa_err slh_dsa_sha2_128s_sign(const slh_dsa_sha2_128s_private_key *private_key,
                                   const uint8_t *message,
                                   size_t message_size,
                                   const uint8_t *context,
                                   size_t context_size,
                                   slh_dsa_sha2_128s_signature *signature_out) {
  return slh_dsa_sha2_128s_sign_with_seed(private_key,
                            message, message_size,
                            context, context_size,
                            NULL, 1, signature_out);
}

static inline slh_dsa_err slh_dsa_sha2_128s_sign_deterministic(const slh_dsa_sha2_128s_private_key *private_key,
                                                 const uint8_t *message,
                                                 size_t message_size,
                                                 const uint8_t *context,
                                                 size_t context_size,
                                                 slh_dsa_sha2_128s_signature *signature_out) {
  return slh_dsa_sha2_128s_sign_with_seed(private_key,
                            message, message_size,
                            context, context_size,
                            NULL, 0, signature_out);
}

slh_dsa_err slh_dsa_sha2_128s_verify(const slh_dsa_sha2_128s_public_key *public_key,
                       const slh_dsa_sha2_128s_signature *signature,
                       const uint8_t *message,
                       size_t message_size,
                       const uint8_t *context,
                       size_t context_size);

slh_dsa_err slh_dsa_sha2_128s_hash_sign_with_seed(const slh_dsa_sha2_128s_private_key *private_key,
                                    const uint8_t *hash,
                                    size_t hash_size,
                                    const uint8_t *context,
                                    size_t context_size,
                                    const uint8_t *hash_oid,
                                    size_t hash_oid_size,
                                    const slh_dsa_sign_seed *seed,
                                    uint8_t hedged,
                                    slh_dsa_sha2_128s_signature *signature_out);

static inline slh_dsa_err slh_dsa_sha2_128s_hash_sign(const slh_dsa_sha2_128s_private_key *private_key,
                                        const uint8_t *hash,
                                        size_t hash_size,
                                        const uint8_t *context,
                                        size_t context_size,
                                        const uint8_t *hash_oid,
                                        size_t hash_oid_size,
                                        slh_dsa_sha2_128s_signature *signature_out) {
  return slh_dsa_sha2_128s_hash_sign_with_seed(private_key,
                                 hash, hash_size,
                                 context, context_size,
                                 hash_oid, hash_oid_size,
                                 NULL, 1, signature_out);
}

static inline slh_dsa_err slh_dsa_sha2_128s_hash_sign_deterministic(const slh_dsa_sha2_128s_private_key *private_key,
                                                      const uint8_t *hash,
                                                      size_t hash_size,
                                                      const uint8_t *context,
                                                      size_t context_size,
                                                      const uint8_t *hash_oid,
                                                      size_t hash_oid_size,
                                                      slh_dsa_sha2_128s_signature *signature_out) {
  return slh_dsa_sha2_128s_hash_sign_with_seed(private_key,
                                 hash, hash_size,
                                 context, context_size,
                                 hash_oid, hash_oid_size,
                                 NULL, 0, signature_out);
}

slh_dsa_err slh_dsa_sha2_128s_hash_verify(const slh_dsa_sha2_128s_public_key *public_key,
                            const slh_dsa_sha2_128s_signature *signature,
                            const uint8_t *hash,
                            size_t hash_size,
                            const uint8_t *context,
                            size_t context_size,
                            const uint8_t *hash_oid,
                            size_t hash_oid_size);


/* slh_dsa_sha2_128f */
slh_dsa_err slh_dsa_sha2_128f_keygen_from_seed(const slh_dsa_keygen_seed *seed,
                                 slh_dsa_sha2_128f_public_key *public_out,
                                 slh_dsa_sha2_128f_private_key *private_out);

static inline slh_dsa_err slh_dsa_sha2_128f_keygen(slh_dsa_sha2_128f_public_key *public_out,
                                     slh_dsa_sha2_128f_private_key *private_out) {
  return slh_dsa_sha2_128f_keygen_from_seed(NULL, public_out, private_out);
}

slh_dsa_err slh_dsa_sha2_128f_get_public_key(const slh_dsa_sha2_128f_private_key *private_key,
                               slh_dsa_sha2_128f_public_key *public_out);

slh_dsa_err slh_dsa_sha2_128f_sign_with_seed(const slh_dsa_sha2_128f_private_key *private_key,
                               const uint8_t *message,
                               size_t message_size,
                               const uint8_t *context,
                               size_t context_size,
                               const slh_dsa_sign_seed *seed,
                               uint8_t hedged,
                               slh_dsa_sha2_128f_signature *signature_out);

static inline slh_dsa_err slh_dsa_sha2_128f_sign(const slh_dsa_sha2_128f_private_key *private_key,
                                   const uint8_t *message,
                                   size_t message_size,
                                   const uint8_t *context,
                                   size_t context_size,
                                   slh_dsa_sha2_128f_signature *signature_out) {
  return slh_dsa_sha2_128f_sign_with_seed(private_key,
                            message, message_size,
                            context, context_size,
                            NULL, 1, signature_out);
}

static inline slh_dsa_err slh_dsa_sha2_128f_sign_deterministic(const slh_dsa_sha2_128f_private_key *private_key,
                                                 const uint8_t *message,
                                                 size_t message_size,
                                                 const uint8_t *context,
                                                 size_t context_size,
                                                 slh_dsa_sha2_128f_signature *signature_out) {
  return slh_dsa_sha2_128f_sign_with_seed(private_key,
                            message, message_size,
                            context, context_size,
                            NULL, 0, signature_out);
}

slh_dsa_err slh_dsa_sha2_128f_verify(const slh_dsa_sha2_128f_public_key *public_key,
                       const slh_dsa_sha2_128f_signature *signature,
                       const uint8_t *message,
                       size_t message_size,
                       const uint8_t *context,
                       size_t context_size);

slh_dsa_err slh_dsa_sha2_128f_hash_sign_with_seed(const slh_dsa_sha2_128f_private_key *private_key,
                                    const uint8_t *hash,
                                    size_t hash_size,
                                    const uint8_t *context,
                                    size_t context_size,
                                    const uint8_t *hash_oid,
                                    size_t hash_oid_size,
                                    const slh_dsa_sign_seed *seed,
                                    uint8_t hedged,
                                    slh_dsa_sha2_128f_signature *signature_out);

static inline slh_dsa_err slh_dsa_sha2_128f_hash_sign(const slh_dsa_sha2_128f_private_key *private_key,
                                        const uint8_t *hash,
                                        size_t hash_size,
                                        const uint8_t *context,
                                        size_t context_size,
                                        const uint8_t *hash_oid,
                                        size_t hash_oid_size,
                                        slh_dsa_sha2_128f_signature *signature_out) {
  return slh_dsa_sha2_128f_hash_sign_with_seed(private_key,
                                 hash, hash_size,
                                 context, context_size,
                                 hash_oid, hash_oid_size,
                                 NULL, 1, signature_out);
}

static inline slh_dsa_err slh_dsa_sha2_128f_hash_sign_deterministic(const slh_dsa_sha2_128f_private_key *private_key,
                                                      const uint8_t *hash,
                                                      size_t hash_size,
                                                      const uint8_t *context,
                                                      size_t context_size,
                                                      const uint8_t *hash_oid,
                                                      size_t hash_oid_size,
                                                      slh_dsa_sha2_128f_signature *signature_out) {
  return slh_dsa_sha2_128f_hash_sign_with_seed(private_key,
                                 hash, hash_size,
                                 context, context_size,
                                 hash_oid, hash_oid_size,
                                 NULL, 0, signature_out);
}

slh_dsa_err slh_dsa_sha2_128f_hash_verify(const slh_dsa_sha2_128f_public_key *public_key,
                            const slh_dsa_sha2_128f_signature *signature,
                            const uint8_t *hash,
                            size_t hash_size,
                            const uint8_t *context,
                            size_t context_size,
                            const uint8_t *hash_oid,
                            size_t hash_oid_size);


/* slh_dsa_shake_128s */
slh_dsa_err slh_dsa_shake_128s_keygen_from_seed(const slh_dsa_keygen_seed *seed,
                                 slh_dsa_shake_128s_public_key *public_out,
                                 slh_dsa_shake_128s_private_key *private_out);

static inline slh_dsa_err slh_dsa_shake_128s_keygen(slh_dsa_shake_128s_public_key *public_out,
                                     slh_dsa_shake_128s_private_key *private_out) {
  return slh_dsa_shake_128s_keygen_from_seed(NULL, public_out, private_out);
}

slh_dsa_err slh_dsa_shake_128s_get_public_key(const slh_dsa_shake_128s_private_key *private_key,
                               slh_dsa_shake_128s_public_key *public_out);

slh_dsa_err slh_dsa_shake_128s_sign_with_seed(const slh_dsa_shake_128s_private_key *private_key,
                               const uint8_t *message,
                               size_t message_size,
                               const uint8_t *context,
                               size_t context_size,
                               const slh_dsa_sign_seed *seed,
                               uint8_t hedged,
                               slh_dsa_shake_128s_signature *signature_out);

static inline slh_dsa_err slh_dsa_shake_128s_sign(const slh_dsa_shake_128s_private_key *private_key,
                                   const uint8_t *message,
                                   size_t message_size,
                                   const uint8_t *context,
                                   size_t context_size,
                                   slh_dsa_shake_128s_signature *signature_out) {
  return slh_dsa_shake_128s_sign_with_seed(private_key,
                            message, message_size,
                            context, context_size,
                            NULL, 1, signature_out);
}

static inline slh_dsa_err slh_dsa_shake_128s_sign_deterministic(const slh_dsa_shake_128s_private_key *private_key,
                                                 const uint8_t *message,
                                                 size_t message_size,
                                                 const uint8_t *context,
                                                 size_t context_size,
                                                 slh_dsa_shake_128s_signature *signature_out) {
  return slh_dsa_shake_128s_sign_with_seed(private_key,
                            message, message_size,
                            context, context_size,
                            NULL, 0, signature_out);
}

slh_dsa_err slh_dsa_shake_128s_verify(const slh_dsa_shake_128s_public_key *public_key,
                       const slh_dsa_shake_128s_signature *signature,
                       const uint8_t *message,
                       size_t message_size,
                       const uint8_t *context,
                       size_t context_size);

slh_dsa_err slh_dsa_shake_128s_hash_sign_with_seed(const slh_dsa_shake_128s_private_key *private_key,
                                    const uint8_t *hash,
                                    size_t hash_size,
                                    const uint8_t *context,
                                    size_t context_size,
                                    const uint8_t *hash_oid,
                                    size_t hash_oid_size,
                                    const slh_dsa_sign_seed *seed,
                                    uint8_t hedged,
                                    slh_dsa_shake_128s_signature *signature_out);

static inline slh_dsa_err slh_dsa_shake_128s_hash_sign(const slh_dsa_shake_128s_private_key *private_key,
                                        const uint8_t *hash,
                                        size_t hash_size,
                                        const uint8_t *context,
                                        size_t context_size,
                                        const uint8_t *hash_oid,
                                        size_t hash_oid_size,
                                        slh_dsa_shake_128s_signature *signature_out) {
  return slh_dsa_shake_128s_hash_sign_with_seed(private_key,
                                 hash, hash_size,
                                 context, context_size,
                                 hash_oid, hash_oid_size,
                                 NULL, 1, signature_out);
}

static inline slh_dsa_err slh_dsa_shake_128s_hash_sign_deterministic(const slh_dsa_shake_128s_private_key *private_key,
                                                      const uint8_t *hash,
                                                      size_t hash_size,
                                                      const uint8_t *context,
                                                      size_t context_size,
                                                      const uint8_t *hash_oid,
                                                      size_t hash_oid_size,
                                                      slh_dsa_shake_128s_signature *signature_out) {
  return slh_dsa_shake_128s_hash_sign_with_seed(private_key,
                                 hash, hash_size,
                                 context, context_size,
                                 hash_oid, hash_oid_size,
                                 NULL, 0, signature_out);
}

slh_dsa_err slh_dsa_shake_128s_hash_verify(const slh_dsa_shake_128s_public_key *public_key,
                            const slh_dsa_shake_128s_signature *signature,
                            const uint8_t *hash,
                            size_t hash_size,
                            const uint8_t *context,
                            size_t context_size,
                            const uint8_t *hash_oid,
                            size_t hash_oid_size);


/* slh_dsa_shake_128f */
slh_dsa_err slh_dsa_shake_128f_keygen_from_seed(const slh_dsa_keygen_seed *seed,
                                 slh_dsa_shake_128f_public_key *public_out,
                                 slh_dsa_shake_128f_private_key *private_out);

static inline slh_dsa_err slh_dsa_shake_128f_keygen(slh_dsa_shake_128f_public_key *public_out,
                                     slh_dsa_shake_128f_private_key *private_out) {
  return slh_dsa_shake_128f_keygen_from_seed(NULL, public_out, private_out);
}

slh_dsa_err slh_dsa_shake_128f_get_public_key(const slh_dsa_shake_128f_private_key *private_key,
                               slh_dsa_shake_128f_public_key *public_out);

slh_dsa_err slh_dsa_shake_128f_sign_with_seed(const slh_dsa_shake_128f_private_key *private_key,
                               const uint8_t *message,
                               size_t message_size,
                               const uint8_t *context,
                               size_t context_size,
                               const slh_dsa_sign_seed *seed,
                               uint8_t hedged,
                               slh_dsa_shake_128f_signature *signature_out);

static inline slh_dsa_err slh_dsa_shake_128f_sign(const slh_dsa_shake_128f_private_key *private_key,
                                   const uint8_t *message,
                                   size_t message_size,
                                   const uint8_t *context,
                                   size_t context_size,
                                   slh_dsa_shake_128f_signature *signature_out) {
  return slh_dsa_shake_128f_sign_with_seed(private_key,
                            message, message_size,
                            context, context_size,
                            NULL, 1, signature_out);
}

static inline slh_dsa_err slh_dsa_shake_128f_sign_deterministic(const slh_dsa_shake_128f_private_key *private_key,
                                                 const uint8_t *message,
                                                 size_t message_size,
                                                 const uint8_t *context,
                                                 size_t context_size,
                                                 slh_dsa_shake_128f_signature *signature_out) {
  return slh_dsa_shake_128f_sign_with_seed(private_key,
                            message, message_size,
                            context, context_size,
                            NULL, 0, signature_out);
}

slh_dsa_err slh_dsa_shake_128f_verify(const slh_dsa_shake_128f_public_key *public_key,
                       const slh_dsa_shake_128f_signature *signature,
                       const uint8_t *message,
                       size_t message_size,
                       const uint8_t *context,
                       size_t context_size);

slh_dsa_err slh_dsa_shake_128f_hash_sign_with_seed(const slh_dsa_shake_128f_private_key *private_key,
                                    const uint8_t *hash,
                                    size_t hash_size,
                                    const uint8_t *context,
                                    size_t context_size,
                                    const uint8_t *hash_oid,
                                    size_t hash_oid_size,
                                    const slh_dsa_sign_seed *seed,
                                    uint8_t hedged,
                                    slh_dsa_shake_128f_signature *signature_out);

static inline slh_dsa_err slh_dsa_shake_128f_hash_sign(const slh_dsa_shake_128f_private_key *private_key,
                                        const uint8_t *hash,
                                        size_t hash_size,
                                        const uint8_t *context,
                                        size_t context_size,
                                        const uint8_t *hash_oid,
                                        size_t hash_oid_size,
                                        slh_dsa_shake_128f_signature *signature_out) {
  return slh_dsa_shake_128f_hash_sign_with_seed(private_key,
                                 hash, hash_size,
                                 context, context_size,
                                 hash_oid, hash_oid_size,
                                 NULL, 1, signature_out);
}

static inline slh_dsa_err slh_dsa_shake_128f_hash_sign_deterministic(const slh_dsa_shake_128f_private_key *private_key,
                                                      const uint8_t *hash,
                                                      size_t hash_size,
                                                      const uint8_t *context,
                                                      size_t context_size,
                                                      const uint8_t *hash_oid,
                                                      size_t hash_oid_size,
                                                      slh_dsa_shake_128f_signature *signature_out) {
  return slh_dsa_shake_128f_hash_sign_with_seed(private_key,
                                 hash, hash_size,
                                 context, context_size,
                                 hash_oid, hash_oid_size,
                                 NULL, 0, signature_out);
}

slh_dsa_err slh_dsa_shake_128f_hash_verify(const slh_dsa_shake_128f_public_key *public_key,
                            const slh_dsa_shake_128f_signature *signature,
                            const uint8_t *hash,
                            size_t hash_size,
                            const uint8_t *context,
                            size_t context_size,
                            const uint8_t *hash_oid,
                            size_t hash_oid_size);

#ifdef  __cplusplus
}
#endif
#endif /* __FIPS205_H__ */
