#![no_main]
use libfuzzer_sys::fuzz_target;
use fips205::{
    slh_dsa_sha2_128f,  // Using slh_dsa_sha2_128f as example, could test other parameter sets
    traits::{SerDes, Signer, Verifier},
    Ph,
};

fuzz_target!(|data: &[u8]| {
    // Need at least some bytes for our test cases
    if data.len() < 32 {
        return;
    }

    // Generate a valid key pair first
    if let Ok((pk, sk)) = slh_dsa_sha2_128f::try_keygen() {
        // Split fuzz data into message and context
        let split_point = data.len() % 255;
        let message = &data[split_point..];
        let context = &data[..split_point];

        // Test 1: Regular verification with valid signature
        if let Ok(valid_sig) = sk.try_sign(message, context, true) {
            let _ = pk.verify(message, &valid_sig, context);
        }

        // Test 2: Hash verification with valid signature
        if let Ok(valid_hash_sig) = sk.try_hash_sign(message, context, &Ph::SHA256, true) {
            let _ = pk.hash_verify(message, &valid_hash_sig, context, &Ph::SHA256);
        }

        // Test 3: Try to deserialize and verify with potentially malformed public key
        if let Ok(maybe_pk) = slh_dsa_sha2_128f::PublicKey::try_from_bytes(
            &pk.clone().into_bytes()  // Use valid key bytes but could use fuzzed data instead
        ) {
            if let Ok(sig) = sk.try_sign(message, context, true) {
                let _ = maybe_pk.verify(message, &sig, context);
            }
        }

        // Test 4: Verify with modified message
        if let Ok(sig) = sk.try_sign(message, context, true) {
            let mut modified_message = message.to_vec();
            if !modified_message.is_empty() {
                modified_message[0] ^= 1; // Flip one bit
                let _ = pk.verify(&modified_message, &sig, context);
            }
        }
    }
});
