#include <stdio.h>
#include "../fips205.h"


int main(int argc, const char **argv) {
    SLHDSA_public_key public;
    SLHDSA_private_key private;
    SLHDSA_signature sig;
    uint8_t message[] = { 0x00, 0x11, 0x22 };

    // Happy path
    if (SLHDSA_keygen(&public, &private)) return 1;
    if (SLHDSA_sign(message, sizeof message, &private, &sig)) return 1;
    if (SLHDSA_verify(message, sizeof message, &public, &sig)) return 1;

    // Verify should fail now
    message[0] = 99;
    if (SLHDSA_verify(message, sizeof message, &public, &sig) != SLH_DSA_VERIFY_ERROR) return 1;

    // Null parameters
    if (SLHDSA_keygen(&public, NULL) != SLH_DSA_NULL_PTR_ERROR) {
        fprintf (stderr, "keygen should have failed with NULL private key\n");
        return 1;
    }
    if (SLHDSA_keygen(NULL, &private) != SLH_DSA_NULL_PTR_ERROR) {
        fprintf (stderr, "keygen should have failed with NULL public key\n");
        return 1;
    }

    if (SLHDSA_sign(NULL, sizeof message, &private, &sig) != SLH_DSA_NULL_PTR_ERROR) {
        fprintf (stderr, "sign should have failed with NULL message\n");
        return 1;
    }
    if (SLHDSA_sign(message, sizeof message, NULL, &sig) != SLH_DSA_NULL_PTR_ERROR) {
        fprintf (stderr, "sign should have failed with NULL private key\n");
        return 1;
    }
    if (SLHDSA_sign(message, sizeof message, &private, NULL) != SLH_DSA_NULL_PTR_ERROR) {
        fprintf (stderr, "sign should have failed with NULL signature\n");
        return 1;
    }
}