#include <fips205.h>

int from_b(void);

int main(void) {
  if (slh_dsa_sha2_128s_keygen(NULL, NULL) == SLH_DSA_OK)
    return 1;
  if (from_b() != SLH_DSA_SHA2_256[0])
    return 2;
  return 0;
}
