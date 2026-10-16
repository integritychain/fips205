// Negative tests for input checking.

#![cfg(feature = "slh-dsa-sha2-128f")]

use fips205::pre_hash;
use fips205::slh_dsa_sha2_128f;
use fips205::traits::{KeyGen, Signer, Verifier};
use rand_chacha::rand_core::SeedableRng;


// HashSLH-DSA takes the digest, not the message. For a `pre_hash` OID the digest must have that
// function's output length, so a message passed in its place is an error rather than a signature
// no other implementation verifies. Other OIDs must be DER-encoded, which fixes where the OID ends
// and the digest begins in M′.
#[test]
fn hash_sign_digest_and_oid_checks() {
    let (pk, sk) = slh_dsa_sha2_128f::KG::keygen_from_seed(&[1u8; 16], &[2u8; 16], &[3u8; 16]);
    let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(123);
    let ctx = b"ctx";

    for (oid, len) in [
        (&pre_hash::SHA2_224[..], 28),
        (&pre_hash::SHA2_256, 32),
        (&pre_hash::SHA2_384, 48),
        (&pre_hash::SHA2_512, 64),
        (&pre_hash::SHA2_512_224, 28),
        (&pre_hash::SHA2_512_256, 32),
        (&pre_hash::SHA3_224, 28),
        (&pre_hash::SHA3_256, 32),
        (&pre_hash::SHA3_384, 48),
        (&pre_hash::SHA3_512, 64),
        (&pre_hash::SHAKE_128, 32),
        (&pre_hash::SHAKE_256, 64),
    ] {
        let digest = [7u8; 65];
        let sig = sk.try_hash_sign_with_rng(&mut rng, &digest[..len], ctx, oid, false).unwrap();
        assert!(pk.hash_verify(&digest[..len], &sig, ctx, oid));
        for bad_len in [0, len - 1, len + 1] {
            assert_eq!(
                sk.try_hash_sign_with_rng(&mut rng, &digest[..bad_len], ctx, oid, false).err(),
                Some("HashSLH-DSA.Sign: digest length does not match the OID")
            );
            assert!(!pk.hash_verify(&digest[..bad_len], &sig, ctx, oid));
        }
    }

    // A message where the digest belongs (the 0.4 API hashed the message itself)
    assert!(sk.try_hash_sign_with_rng(&mut rng, b"hello", ctx, &pre_hash::SHA2_256, true).is_err());

    // OIDs that are empty or not DER
    let digest = [7u8; 32];
    let sig = sk.try_hash_sign_with_rng(&mut rng, &digest, ctx, &pre_hash::SHA2_256, true).unwrap();
    assert_eq!(
        sk.try_hash_sign_with_rng(&mut rng, &digest, ctx, &[], true).err(),
        Some("HashSLH-DSA.Sign: OID is empty")
    );
    for oid in
        [&[0xffu8][..], &[0x06], &[0x06, 0x00], &[0x04, 0x01, 0x00], &pre_hash::SHA2_256[..10]]
    {
        assert_eq!(
            sk.try_hash_sign_with_rng(&mut rng, &digest, ctx, oid, true).err(),
            Some("HashSLH-DSA.Sign: OID is not DER encoded")
        );
        assert!(!pk.hash_verify(&digest, &sig, ctx, oid));
    }

    // The same bytes of OID || digest, split elsewhere, do not verify
    let mut shifted = vec![pre_hash::SHA2_256[10]];
    shifted.extend_from_slice(&digest);
    assert!(!pk.hash_verify(&shifted, &sig, ctx, &pre_hash::SHA2_256[..10]));

    // Another DER OID (here 1.2.3.4) takes a digest of up to 1024 bytes
    let other_oid = [0x06, 0x03, 0x2a, 0x03, 0x04];
    for len in [1, 20, 1024] {
        let digest = vec![9u8; len];
        let sig = sk.try_hash_sign_with_rng(&mut rng, &digest, ctx, &other_oid, true).unwrap();
        assert!(pk.hash_verify(&digest, &sig, ctx, &other_oid));
    }
    assert!(sk.try_hash_sign_with_rng(&mut rng, &[9u8; 1025], ctx, &other_oid, true).is_err());
}
