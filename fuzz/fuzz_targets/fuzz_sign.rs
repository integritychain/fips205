#![no_main]
use libfuzzer_sys::fuzz_target;
use fips205::{
    pre_hash,
    slh_dsa_sha2_128f, // Using sha2_128f as an example parameter set
    traits::Signer,
};
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
        let oid: &[u8] = match input.hash_function % 3 {
            0 => &pre_hash::SHA2_256,
            1 => &pre_hash::SHA2_512,
            _ => &pre_hash::SHAKE_256,
        };
        let ctx = &input.context[..input.context.len() % 255];
        // The library does not hash this digest. Cap it so the 1024-byte check is not the only path.
        let digest = &input.message[..input.message.len().min(64)];

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
