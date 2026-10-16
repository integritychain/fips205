#![no_main]
use fips205::{
    pre_hash,
    slh_dsa_sha2_128f, // Using sha2_128f as an example parameter set
    traits::Signer,
};
use libfuzzer_sys::fuzz_target;
use rand_core::OsRng;

// Wrapper struct to help organize the fuzz input
#[derive(arbitrary::Arbitrary, Debug)]
struct FuzzInput {
    message: Vec<u8>,
    context: Vec<u8>,
    hedged: bool,
    use_hash: bool,
    hash_function: u8,
}

fuzz_target!(|input: FuzzInput| {
    // Generate a keypair first (using real RNG for this part)
    if let Ok((_, sk)) = slh_dsa_sha2_128f::try_keygen() {
        // The digest has the length of the OID's hash function
        let (oid, len): (&[u8], usize) = match input.hash_function % 3 {
            0 => (&pre_hash::SHA2_256, 32),
            1 => (&pre_hash::SHA2_512, 64),
            _ => (&pre_hash::SHAKE_256, 64),
        };
        let ctx = &input.context[..input.context.len() % 255];
        // The library does not hash this digest. Take it from the message, zero-padded.
        let mut buf = [0u8; 64];
        let n = input.message.len().min(64);
        buf[..n].copy_from_slice(&input.message[..n]);
        let digest = &buf[..len];

        // Test regular signing
        let _ = sk.try_sign_with_rng(&mut OsRng, &input.message, ctx, input.hedged);

        // Test hash signing
        if input.use_hash {
            let _ = sk.try_hash_sign_with_rng(&mut OsRng, digest, ctx, oid, input.hedged);
        }

        // Test public key derivation
        let _pk = sk.get_public_key();
    }
});
