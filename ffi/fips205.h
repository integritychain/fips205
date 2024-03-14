#ifndef FIPS205_FIPS205_H
#define FIPS205_FIPS205_H

#include <stdint.h>

typedef uint8_t slh_dsa_err;

const slh_dsa_err SLH_DSA_OK = 0;
const slh_dsa_err SLH_DSA_NULL_PTR_ERROR = 1;
const slh_dsa_err SLH_DSA_SERIALIZATION_ERROR = 2;
const slh_dsa_err SLH_DSA_DESERIALIZATION_ERROR = 3;
const slh_dsa_err SLH_DSA_KEYGEN_ERROR = 4;
const slh_dsa_err SLH_DSA_SIGN_ERROR = 5;
const slh_dsa_err SLH_DSA_VERIFY_ERROR = 6;

typedef struct slh_dsa_sha2_128f_public_key {
    uint8_t data[32];
} slh_dsa_sha2_128f_public_key;

typedef struct slh_dsa_sha2_128f_private_key {
    uint8_t data[64];
} slh_dsa_sha2_128f_private_key;

typedef struct slh_dsa_sha2_128f_signature {
    uint8_t data[17088];
} slh_dsa_sha2_128f_signature;


#ifdef  __cplusplus
extern "C" {
#endif

slh_dsa_err slh_dsa_sha2_128f_keygen(slh_dsa_sha2_128f_public_key *public_out,
                                     slh_dsa_sha2_128f_private_key *private_out);

slh_dsa_err slh_dsa_sha2_128f_sign(const uint8_t *message_buf,
                                   int message_length,
                                   const slh_dsa_sha2_128f_private_key *private,
                                   slh_dsa_sha2_128f_signature *signature_out);

slh_dsa_err slh_dsa_sha2_128f_verify(const uint8_t *message_buf,
                                   int message_length,
                                   const slh_dsa_sha2_128f_public_key *public,
                                   const slh_dsa_sha2_128f_signature *signature_out);


#ifdef  __cplusplus
} // extern "C"
#endif
#endif //FIPS205_FIPS205_H
