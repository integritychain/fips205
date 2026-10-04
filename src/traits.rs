use rand_core::CryptoRngCore;
use rand_core::RngCore;
use rand_core::CryptoRng;

#[cfg(feature = "default-rng")]
use rand_core::OsRng;


/// The `KeyGen` trait is defined to allow trait objects.
pub trait KeyGen {
    /// A public key specific to the chosen security parameter set, e.g., `slh_dsa_shake_128s`, `slh_dsa_sha2_128s` etc
    type PublicKey;
    /// A private (secret) key specific to the chosen security parameter set, e.g., `slh_dsa_shake_128s`, `slh_dsa_sha2_128s` etc
    type PrivateKey;


    /// Generates a public and private key pair specific to this security parameter set.
    /// This function utilizes the **OS default** random number generator. Key generation does
    /// not branch on the secret seed. The random number generator is not part of this claim.
    /// # Errors
    /// Returns an error when the random number generator fails.
    /// # Examples
    /// ```rust
    /// # use std::error::Error;
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// # #[cfg(all(feature = "slh-dsa-shake-128s", feature = "default-rng"))] {
    /// use fips205::slh_dsa_shake_128s; // Could use any of the twelve security parameter sets.
    /// use fips205::traits::{SerDes, Signer, Verifier};
    ///
    /// let msg_bytes = [0u8, 1, 2, 3, 4, 5, 6, 7];
    ///
    /// // Generate both public and secret keys. This only fails when the OS rng fails.
    /// let (pk1, sk) = slh_dsa_shake_128s::try_keygen()?;
    /// // Use the secret key to generate a signature. The second parameter is the
    /// // context string (often just an empty &[]), and the last parameter selects
    /// // the preferred hedged variant. This fails when the OS rng fails or the context is longer than 255 bytes.
    /// let sig_bytes = sk.try_sign(&msg_bytes, b"context", true)?;
    ///
    /// // Serialize the public key, and send with message and signature bytes. These
    /// // statements model sending byte arrays over the wire.
    /// let (pk_send, msg_send, sig_send) = (pk1.into_bytes(), msg_bytes, sig_bytes);
    /// let (pk_recv, msg_recv, sig_recv) = (pk_send, msg_send, sig_send);
    ///
    /// // A public key of the right length always decodes.
    /// let pk2 = slh_dsa_shake_128s::PublicKey::try_from_bytes(pk_recv)?;
    /// // Use the public key to verify the msg signature
    /// let v = pk2.verify(&msg_recv, &sig_recv, b"context");
    /// assert!(v);
    /// # }
    /// # Ok(())
    /// # }
    /// ```
    #[cfg(feature = "default-rng")]
    fn try_keygen() -> Result<(Self::PublicKey, Self::PrivateKey), &'static str> {
        Self::try_keygen_with_rng(&mut OsRng)
    }


    /// Generates a public and private key pair specific to this security parameter set.
    /// This function utilizes the **provided** random number generator. Key generation does
    /// not branch on the secret seed. The random number generator is not part of this claim.
    /// # Errors
    /// Returns an error when the random number generator fails.
    /// # Examples
    /// ```rust
    /// # use std::error::Error;
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// # #[cfg(feature = "slh-dsa-shake-128s")] {
    /// use fips205::slh_dsa_shake_128s; // Could use any of the twelve security parameter sets.
    /// use fips205::traits::{SerDes, Signer, Verifier};
    /// use rand_chacha::rand_core::SeedableRng;
    ///
    /// let msg_bytes = [0u8, 1, 2, 3, 4, 5, 6, 7];
    /// let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(123);
    ///
    /// // Generate both public and secret keys. This only fails when the provided rng fails.
    /// let (pk1, sk) = slh_dsa_shake_128s::try_keygen_with_rng(&mut rng)?;
    /// // Use the secret key to generate a signature. The second parameter is the
    /// // context string (often just an empty &[]), and the last parameter selects
    /// // the preferred hedged variant. This fails when the provided rng fails or the context is longer than 255 bytes.
    /// let sig_bytes = sk.try_sign_with_rng(&mut rng, &msg_bytes, b"context", true)?;
    ///
    ///
    /// // Serialize the public key, and send with message and signature bytes. These
    /// // statements model sending byte arrays over the wire.
    /// let (pk_send, msg_send, sig_send) = (pk1.into_bytes(), msg_bytes, sig_bytes);
    /// let (pk_recv, msg_recv, sig_recv) = (pk_send, msg_send, sig_send);
    ///
    ///
    /// // A public key of the right length always decodes.
    /// let pk2 = slh_dsa_shake_128s::PublicKey::try_from_bytes(pk_recv)?;
    /// // Use the public key to verify the msg signature
    /// let v = pk2.verify(&msg_recv, &sig_recv, b"context");
    /// assert!(v);
    /// # }
    /// # Ok(())
    /// # }
    /// ```
    fn try_keygen_with_rng(
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Self::PublicKey, Self::PrivateKey), &'static str>;

    /// Generates a public and private key pair specific to this security parameter set.
    /// This function utilizes **three provided seeds** rather than a random number
    /// generator in order to deterministically generate keys. Key generation does not
    /// branch on the secret seed.
    /// # Examples
    /// ```rust
    /// # use std::error::Error;
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// # #[cfg(feature = "slh-dsa-shake-128s")] {
    /// use fips205::slh_dsa_shake_128s; // Could use any of the twelve security parameter sets.
    /// use fips205::traits::{KeyGen, SerDes, Signer, Verifier};
    /// use rand_chacha::rand_core::SeedableRng;
    ///
    /// let msg_bytes = [0u8, 1, 2, 3, 4, 5, 6, 7];
    /// let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(123);
    ///
    /// // Generate both public and secret keys from the provided seeds.
    /// let (pk1, sk) = slh_dsa_shake_128s::KG::keygen_from_seed(&[0u8; slh_dsa_shake_128s::N],
    ///                 &[1u8; slh_dsa_shake_128s::N], &[2u8; slh_dsa_shake_128s::N]);
    /// // Use the secret key to generate a signature. The second parameter is the
    /// // context string (often just an empty &[]), and the last parameter selects
    /// // the preferred hedged variant. This fails when the provided rng fails or the context is longer than 255 bytes.
    /// let sig_bytes = sk.try_sign_with_rng(&mut rng, &msg_bytes, b"context", true)?;
    ///
    ///
    /// // Serialize the public key, and send with message and signature bytes. These
    /// // statements model sending byte arrays over the wire.
    /// let (pk_send, msg_send, sig_send) = (pk1.into_bytes(), msg_bytes, sig_bytes);
    /// let (pk_recv, msg_recv, sig_recv) = (pk_send, msg_send, sig_send);
    ///
    ///
    /// // A public key of the right length always decodes.
    /// let pk2 = slh_dsa_shake_128s::PublicKey::try_from_bytes(pk_recv)?;
    /// // Use the public key to verify the msg signature
    /// let v = pk2.verify(&msg_recv, &sig_recv, b"context");
    /// assert!(v);
    /// # }
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    fn keygen_from_seed<const N: usize>(
        sk_seed: &[u8; N], sk_prf: &[u8; N], pk_seed: &[u8; N]
    ) -> (Self::PublicKey, Self::PrivateKey) {
        Self::try_keygen_with_rng(&mut DummyRng {data: [*sk_seed, *sk_prf, *pk_seed], i: 0 }).expect("rng will not fail")
    }
}

// This is for the deterministic keygen functions; will be refactored more nicely
struct DummyRng<const N: usize> { data: [[u8; N]; 3], i: usize }

impl<const N: usize> RngCore for DummyRng<N> {
    fn next_u32(&mut self) -> u32 { unimplemented!() }

    fn next_u64(&mut self) -> u64 { unimplemented!() }

    fn fill_bytes(&mut self, _out: &mut [u8]) { unimplemented!() }

    fn try_fill_bytes(&mut self, out: &mut [u8]) -> Result<(), rand_core::Error> {
        out.copy_from_slice(&self.data[self.i]);
        self.i += 1;
        Ok(())
    }
}

impl<const N: usize> CryptoRng for DummyRng<N> {}


/// The Signer trait is implemented for the `PrivateKey` struct on each of the security parameter sets
pub trait Signer {
    /// The signature is specific to the chosen security parameter set, e.g., `slh_dsa_shake_128s`, `slh_dsa_sha2_128s` etc
    type Signature;
    /// The public key that corresponds to the private/secret key
    type PublicKey;

    /// Attempt to sign the given message, returning a digital signature on success, or an error if
    /// something went wrong. This function utilizes the **OS default** random number generator.
    /// Signing does not branch on the secret seed. WOTS chain lengths and FORS indices follow
    /// the message digest, which is public once `R` is in the signature. The random number
    /// generator is not part of this claim. The context is often empty (`&[]`).
    /// # Errors
    /// Returns an error when the random number generator fails or `ctx` is longer than 255 bytes.
    /// # Examples
    /// ```rust
    /// # use std::error::Error;
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// # #[cfg(all(feature = "slh-dsa-shake-128s", feature = "default-rng"))] {
    /// use fips205::slh_dsa_shake_128s; // Could use any of the twelve security parameter sets.
    /// use fips205::traits::{SerDes, Signer, Verifier};
    ///
    /// let msg_bytes = [0u8, 1, 2, 3, 4, 5, 6, 7];
    ///
    /// // Generate both public and secret keys. This only fails when the OS rng fails.
    /// let (pk1, sk) = slh_dsa_shake_128s::try_keygen()?;
    /// // Use the secret key to generate a signature. The second parameter is the
    /// // context string (often just an empty &[]), and the last parameter selects
    /// // the preferred hedged variant. This fails when the OS rng fails or the context is longer than 255 bytes.
    /// let sig_bytes = sk.try_sign(&msg_bytes, b"context", true)?;
    ///
    /// // Serialize the public key, and send with message and signature bytes. These
    /// // statements model sending byte arrays over the wire.
    /// let (pk_send, msg_send, sig_send) = (pk1.into_bytes(), msg_bytes, sig_bytes);
    /// let (pk_recv, msg_recv, sig_recv) = (pk_send, msg_send, sig_send);
    ///
    /// // A public key of the right length always decodes.
    /// let pk2 = slh_dsa_shake_128s::PublicKey::try_from_bytes(pk_recv)?;
    /// // Use the public key to verify the msg signature
    /// let v = pk2.verify(&msg_recv, &sig_recv, b"context");
    /// assert!(v);
    /// # }
    /// # Ok(())
    /// # }
    /// ```
    #[cfg(feature = "default-rng")]
    fn try_sign(
        &self, message: &[u8], ctx: &[u8], hedged: bool,
    ) -> Result<Self::Signature, &'static str> {
        self.try_sign_with_rng(&mut OsRng, message, ctx, hedged)
    }


    /// Attempt to sign a given message, returning a digital signature on success, or an
    /// error if something went wrong. This function utilizes a **provided** random number generator.
    /// Signing does not branch on the secret seed. WOTS chain lengths and FORS indices follow
    /// the message digest, which is public once `R` is in the signature. The random number
    /// generator is not part of this claim. The context is often empty (`&[]`).
    ///
    /// # Errors
    /// Returns an error when the random number generator fails or `ctx` is longer than 255 bytes.
    /// # Examples
    /// ```rust
    /// # use std::error::Error;
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// # #[cfg(feature = "slh-dsa-shake-128s")] {
    /// use fips205::slh_dsa_shake_128s; // Could use any of the twelve security parameter sets.
    /// use fips205::traits::{SerDes, Signer, Verifier};
    /// use rand_chacha::rand_core::SeedableRng;
    ///
    /// let msg_bytes = [0u8, 1, 2, 3, 4, 5, 6, 7];
    /// let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(123);
    ///
    /// // Generate both public and secret keys. This only fails when the provided rng fails.
    /// let (pk1, sk) = slh_dsa_shake_128s::try_keygen_with_rng(&mut rng)?;
    /// // Use the secret key to generate a signature. The third parameter is the
    /// // context string (often just an empty &[]), and the last parameter selects
    /// // the preferred hedged variant. This fails when the provided rng fails or the context is longer than 255 bytes.
    /// let sig_bytes = sk.try_sign_with_rng(&mut rng, &msg_bytes, b"context", true)?;
    ///
    ///
    /// // Serialize the public key, and send with message and signature bytes. These
    /// // statements model sending byte arrays over the wire.
    /// let (pk_send, msg_send, sig_send) = (pk1.into_bytes(), msg_bytes, sig_bytes);
    /// let (pk_recv, msg_recv, sig_recv) = (pk_send, msg_send, sig_send);
    ///
    ///
    /// // A public key of the right length always decodes.
    /// let pk2 = slh_dsa_shake_128s::PublicKey::try_from_bytes(pk_recv)?;
    /// // Use the public key to verify the msg signature
    /// let v = pk2.verify(&msg_recv, &sig_recv, b"context");
    /// assert!(v);
    /// # }
    /// # Ok(())
    /// # }
    /// ```
    fn try_sign_with_rng(
        &self, rng: &mut impl CryptoRngCore, message: &[u8], ctx: &[u8], hedged: bool,
    ) -> Result<Self::Signature, &'static str>;


    /// Attempt to sign a precomputed digest, returning a HashSLH-DSA signature on success, or an
    /// error if something went wrong. `hash` is `PH(M)` and `hash_oid` is the DER encoding of that
    /// pre-hash, including the tag and length. [`crate::pre_hash`] provides the NIST CSOR encodings.
    /// This function does not hash `hash` again. It utilizes the **OS default** random number
    /// generator. Signing does not branch on the secret seed. WOTS chain lengths and FORS
    /// indices follow the message digest, which is public once `R` is in the signature. The
    /// random number generator is not part of this claim. The context is often empty (`&[]`).
    /// # Errors
    /// Returns an error when the random number generator fails, the `ctx` is longer than 255 bytes,
    /// `hash_oid` is empty, or `hash` is longer than 1024 bytes.
    /// # Examples
    /// ```rust
    /// # use std::error::Error;
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// # #[cfg(all(feature = "slh-dsa-shake-128s", feature = "default-rng"))] {
    /// use fips205::pre_hash;
    /// use fips205::slh_dsa_shake_128s; // Could use any of the twelve security parameter sets.
    /// use fips205::traits::{SerDes, Signer, Verifier};
    /// use sha2::{Digest, Sha256};
    ///
    /// let msg_bytes = [0u8, 1, 2, 3, 4, 5, 6, 7];
    /// let digest = Sha256::digest(msg_bytes);
    ///
    /// // Generate both public and secret keys. This only fails when the OS rng fails.
    /// let (pk1, sk) = slh_dsa_shake_128s::try_keygen()?;
    /// // Sign the digest. The second parameter is the context string (often just an empty &[]),
    /// // and the last parameter selects the preferred hedged variant.
    /// let sig_bytes = sk.try_hash_sign(&digest, b"context", &pre_hash::SHA2_256, true)?;
    ///
    /// // Serialize the public key, and send with digest and signature bytes. These
    /// // statements model sending byte arrays over the wire.
    /// let (pk_send, hash_send, sig_send) = (pk1.into_bytes(), digest, sig_bytes);
    /// let (pk_recv, hash_recv, sig_recv) = (pk_send, hash_send, sig_send);
    ///
    /// // A public key of the right length always decodes.
    /// let pk2 = slh_dsa_shake_128s::PublicKey::try_from_bytes(pk_recv)?;
    /// // Use the public key to verify the signature on the digest
    /// let v = pk2.hash_verify(&hash_recv, &sig_recv, b"context", &pre_hash::SHA2_256);
    /// assert!(v);
    /// # }
    /// # Ok(())
    /// # }
    /// ```
    #[cfg(feature = "default-rng")]
    fn try_hash_sign(
        &self, hash: &[u8], ctx: &[u8], hash_oid: &[u8], hedged: bool,
    ) -> Result<Self::Signature, &'static str> {
        self.try_hash_sign_with_rng(&mut OsRng, hash, ctx, hash_oid, hedged)
    }


    /// Attempt to sign a precomputed digest, returning a HashSLH-DSA signature on success, or an
    /// error if something went wrong. `hash` is `PH(M)` and `hash_oid` is the DER encoding of that
    /// pre-hash, including the tag and length. [`crate::pre_hash`] provides the NIST CSOR encodings.
    /// This function does not hash `hash` again. It utilizes a **provided** random number generator.
    /// Signing does not branch on the secret seed. WOTS chain lengths and FORS indices follow
    /// the message digest, which is public once `R` is in the signature. The random number
    /// generator is not part of this claim. The context is often empty (`&[]`).
    ///
    /// # Errors
    /// Returns an error when the random number generator fails, the `ctx` is longer than 255 bytes,
    /// `hash_oid` is empty, or `hash` is longer than 1024 bytes.
    /// # Examples
    /// ```rust
    /// # use std::error::Error;
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// # #[cfg(feature = "slh-dsa-shake-128s")] {
    /// use fips205::pre_hash;
    /// use fips205::slh_dsa_shake_128s; // Could use any of the twelve security parameter sets.
    /// use fips205::traits::{SerDes, Signer, Verifier};
    /// use rand_chacha::rand_core::SeedableRng;
    /// use sha2::{Digest, Sha512};
    ///
    /// let msg_bytes = [0u8, 1, 2, 3, 4, 5, 6, 7];
    /// let digest = Sha512::digest(msg_bytes);
    /// let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(123);
    ///
    /// // Generate both public and secret keys. This only fails when the provided rng fails.
    /// let (pk1, sk) = slh_dsa_shake_128s::try_keygen_with_rng(&mut rng)?;
    /// // Sign the digest. The third parameter is the context string (often just an empty &[]),
    /// // and the last parameter selects the preferred hedged variant.
    /// let sig_bytes =
    ///     sk.try_hash_sign_with_rng(&mut rng, &digest, b"context", &pre_hash::SHA2_512, true)?;
    ///
    ///
    /// // Serialize the public key, and send with digest and signature bytes. These
    /// // statements model sending byte arrays over the wire.
    /// let (pk_send, hash_send, sig_send) = (pk1.into_bytes(), digest, sig_bytes);
    /// let (pk_recv, hash_recv, sig_recv) = (pk_send, hash_send, sig_send);
    ///
    ///
    /// // A public key of the right length always decodes.
    /// let pk2 = slh_dsa_shake_128s::PublicKey::try_from_bytes(pk_recv)?;
    /// // Use the public key to verify the signature on the digest
    /// let v = pk2.hash_verify(&hash_recv, &sig_recv, b"context", &pre_hash::SHA2_512);
    /// assert!(v);
    /// # }
    /// # Ok(())
    /// # }
    /// ```
    fn try_hash_sign_with_rng(
        &self, rng: &mut impl CryptoRngCore, hash: &[u8], ctx: &[u8], hash_oid: &[u8], hedged: bool,
    ) -> Result<Self::Signature, &'static str>;


    /// Retrieves the public key associated with this private/secret key
    /// # Examples
    /// ```rust
    /// # #[cfg(feature = "slh-dsa-shake-128s")] {
    /// use fips205::slh_dsa_shake_128s; // Could use any of the twelve security parameter sets.
    /// use fips205::traits::{KeyGen, Signer};
    ///
    /// // Generate a key pair from seeds, and keep only the secret key.
    /// let (_, sk) = slh_dsa_shake_128s::KG::keygen_from_seed(
    ///     &[0u8; slh_dsa_shake_128s::N],
    ///     &[1u8; slh_dsa_shake_128s::N],
    ///     &[2u8; slh_dsa_shake_128s::N],
    /// );
    ///
    /// // The public key can be derived from the secret key
    /// let _pk = sk.get_public_key();
    /// # }
    /// ```
    fn get_public_key(&self) -> Self::PublicKey;
}


/// The Verifier trait is implemented for `PublicKey` on each of the security parameter sets
pub trait Verifier {
    /// The signature is specific to the chosen security parameter set, e.g., `slh_dsa_shake_128s`, `slh_dsa_sha2_128s` etc
    type Signature;


    /// Verifies a digital signature with respect to a `PublicKey`. Verification uses only public
    /// data, so it makes no constant-time claim. The context is often empty (`&[]`). Returns
    /// `false` when `ctx` is longer than 255 bytes or the signature does not verify.
    ///
    /// # Examples
    /// ```rust
    /// # use std::error::Error;
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// # #[cfg(all(feature = "slh-dsa-shake-128s", feature = "default-rng"))] {
    /// use fips205::slh_dsa_shake_128s; // Could use any of the twelve security parameter sets.
    /// use fips205::traits::{SerDes, Signer, Verifier};
    ///
    /// let msg_bytes = [0u8, 1, 2, 3, 4, 5, 6, 7];
    ///
    /// // Generate both public and secret keys. This only fails when the OS rng fails.
    /// let (pk1, sk) = slh_dsa_shake_128s::try_keygen()?;
    /// // Use the secret key to generate a signature. The second parameter is the
    /// // context string (often just an empty &[]), and the last parameter selects
    /// // the preferred hedged variant. This fails when the OS rng fails or the context is longer than 255 bytes.
    /// let sig_bytes = sk.try_sign(&msg_bytes, b"context", true)?;
    ///
    /// // Serialize the public key, and send with message and signature bytes. These
    /// // statements model sending byte arrays over the wire.
    /// let (pk_send, msg_send, sig_send) = (pk1.into_bytes(), msg_bytes, sig_bytes);
    /// let (pk_recv, msg_recv, sig_recv) = (pk_send, msg_send, sig_send);
    ///
    /// // A public key of the right length always decodes.
    /// let pk2 = slh_dsa_shake_128s::PublicKey::try_from_bytes(pk_recv)?;
    /// // Use the public key to verify the msg signature
    /// let v = pk2.verify(&msg_recv, &sig_recv, b"context");
    /// assert!(v);
    /// # }
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    fn verify(&self, message: &[u8], signature: &Self::Signature, ctx: &[u8]) -> bool;


    /// Verifies a HashSLH-DSA signature over a precomputed digest. `hash` is `PH(M)` and `hash_oid`
    /// is the DER encoding of that pre-hash, including the tag and length; see [`crate::pre_hash`].
    /// The caller must supply the same digest and OID that were signed. Verification uses only
    /// public data, so it makes no constant-time claim. Returns `false` when
    /// `ctx` is longer than 255 bytes, `hash_oid` is empty, `hash` is longer than 1024 bytes, or the
    /// signature does not verify.
    ///
    /// # Examples
    /// ```rust
    /// # use std::error::Error;
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// # #[cfg(all(feature = "slh-dsa-shake-128s", feature = "default-rng"))] {
    /// use fips205::pre_hash;
    /// use fips205::slh_dsa_shake_128s; // Could use any of the twelve security parameter sets.
    /// use fips205::traits::{SerDes, Signer, Verifier};
    /// use sha2::{Digest, Sha256};
    ///
    /// let msg_bytes = [0u8, 1, 2, 3, 4, 5, 6, 7];
    /// let digest = Sha256::digest(msg_bytes);
    ///
    /// // Generate both public and secret keys. This only fails when the OS rng fails.
    /// let (pk1, sk) = slh_dsa_shake_128s::try_keygen()?;
    /// // Sign the digest. The second parameter is the context string (often just an empty &[]),
    /// // and the last parameter selects the preferred hedged variant.
    /// let sig_bytes = sk.try_hash_sign(&digest, b"context", &pre_hash::SHA2_256, true)?;
    ///
    /// // Serialize the public key, and send with digest and signature bytes. These
    /// // statements model sending byte arrays over the wire.
    /// let (pk_send, hash_send, sig_send) = (pk1.into_bytes(), digest, sig_bytes);
    /// let (pk_recv, hash_recv, sig_recv) = (pk_send, hash_send, sig_send);
    ///
    /// // A public key of the right length always decodes.
    /// let pk2 = slh_dsa_shake_128s::PublicKey::try_from_bytes(pk_recv)?;
    /// // Use the public key to verify the signature on the digest
    /// let v = pk2.hash_verify(&hash_recv, &sig_recv, b"context", &pre_hash::SHA2_256);
    /// assert!(v);
    /// # }
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    fn hash_verify(
        &self, hash: &[u8], signature: &Self::Signature, ctx: &[u8], hash_oid: &[u8],
    ) -> bool;
}


/// The `SerDes` trait provides for validated serialization and deserialization of fixed size elements
pub trait SerDes {
    /// The fixed-size byte array to be serialized or deserialized
    type ByteArray;


    /// Produces a byte array of fixed-size specific to the struct being serialized.
    ///
    /// Encode a key when the bytes are needed. Decoding a private key costs a key
    /// generation, so keep the `PrivateKey` rather than decoding it on each use.
    /// # Examples
    /// ```rust
    /// # use std::error::Error;
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// # #[cfg(all(feature = "slh-dsa-shake-128s", feature = "default-rng"))] {
    /// use fips205::slh_dsa_shake_128s; // Could use any of the twelve security parameter sets.
    /// use fips205::traits::{SerDes, Signer, Verifier};
    ///
    /// let msg_bytes = [0u8, 1, 2, 3, 4, 5, 6, 7];
    ///
    /// // Generate public/private key pair and signature
    /// let (pk1, sk) = slh_dsa_shake_128s::try_keygen()?;  // Generate both public and secret keys
    /// let sig_bytes = sk.try_sign(&msg_bytes, b"context", true)?;  // Use the secret key to generate a msg signature
    ///
    /// // Serialize the public key, and send with message and signature bytes
    /// let (pk_send, msg_send, sig_send) = (pk1.into_bytes(), msg_bytes, sig_bytes);
    /// let (pk_recv, msg_recv, sig_recv) = (pk_send, msg_send, sig_send);
    ///
    /// // Deserialize the public key, then use it to verify the msg signature
    /// let pk2 = slh_dsa_shake_128s::PublicKey::try_from_bytes(pk_recv)?;
    /// let v = pk2.verify(&msg_recv, &sig_recv, b"context");
    /// assert!(v);
    /// # }
    /// # Ok(())
    /// # }
    /// ```
    fn into_bytes(self) -> Self::ByteArray;


    /// Consumes a byte array of fixed-size specific to the struct being deserialized.
    ///
    /// A public key is `PK.seed` followed by `PK.root`. Every array of that length is
    /// accepted. The `Result` stays so this trait also covers the private key.
    ///
    /// A private key is checked by recomputing `PK.root` from `SK.seed` and `PK.seed`
    /// (FIPS 205 `slh_keygen_internal`). That walk is a full key generation. Decode a
    /// private key once and keep the `PrivateKey`. `SK.prf` is not part of the check.
    ///
    /// # Errors
    /// Returns an error when a private key's stored `PK.root` does not match the value
    /// recomputed from its seeds. Public-key decode does not fail.
    /// # Examples
    /// ```rust
    /// # use std::error::Error;
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// # #[cfg(all(feature = "slh-dsa-shake-128s", feature = "default-rng"))] {
    /// use fips205::slh_dsa_shake_128s; // Could use any of the twelve security parameter sets.
    /// use fips205::traits::{SerDes, Signer, Verifier};
    ///
    /// let msg_bytes = [0u8, 1, 2, 3, 4, 5, 6, 7];
    ///
    /// // Generate public/private key pair and signature
    /// let (pk1, sk) = slh_dsa_shake_128s::try_keygen()?;  // Generate both public and secret keys
    /// let sig_bytes = sk.try_sign(&msg_bytes, b"context", true)?;  // Use the secret key to generate a msg signature
    ///
    /// // Serialize the public key, and send with message and signature bytes
    /// let (pk_send, msg_send, sig_send) = (pk1.into_bytes(), msg_bytes, sig_bytes);
    /// let (pk_recv, msg_recv, sig_recv) = (pk_send, msg_send, sig_send);
    ///
    /// // Deserialize the public key, then use it to verify the msg signature
    /// let pk2 = slh_dsa_shake_128s::PublicKey::try_from_bytes(pk_recv)?;
    /// let v = pk2.verify(&msg_recv, &sig_recv, b"context");
    /// assert!(v);
    /// # }
    /// # Ok(())
    /// # }
    /// ```
    fn try_from_bytes(ba: Self::ByteArray) -> Result<Self, &'static str>
    where
        Self: Sized;
}
