use rand_core::CryptoRngCore;

#[cfg(feature = "default-rng")]
use rand_core::OsRng;


/// The `SerDes` trait provides for validated serialization and deserialization of fixed size elements
pub trait SerDes {
    /// The fixed-size byte array to be serialized or deserialized
    type ByteArray;

    /// Produces a byte array of fixed-size specific to the struct being serialized.
    /// # Examples
    /// ```rust
    /// use fips205::slh_dsa_shake_128s; // Could use any of the twelve security parameter sets.
    /// use fips205::traits::{SerDes, Signer, Verifier};
    /// # use std::error::Error;
    /// #
    /// # fn main() -> Result<(), Box<dyn Error>> {
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
    /// let pk2 = slh_dsa_shake_128s::PublicKey::try_from_bytes(&pk_recv)?;
    /// let v = pk2.try_verify(&msg_recv, &sig_recv, b"context")?;
    /// assert!(v);
    /// # Ok(())
    /// # }
    /// ```
    fn into_bytes(self) -> Self::ByteArray;

    /// Consumes a byte array of fixed-size specific to the struct being deserialized; performs validation
    /// # Errors
    /// Returns an error on malformed input.
    /// # Examples
    /// ```rust
    /// use fips205::slh_dsa_shake_128s; // Could use any of the twelve security parameter sets.
    /// use fips205::traits::{SerDes, Signer, Verifier};
    /// # use std::error::Error;
    /// #
    /// # fn main() -> Result<(), Box<dyn Error>> {
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
    /// let pk2 = slh_dsa_shake_128s::PublicKey::try_from_bytes(&pk_recv)?;
    /// let v = pk2.try_verify(&msg_recv, &sig_recv, b"context")?;
    /// assert!(v);
    /// # Ok(())
    /// # }
    /// ```
    fn try_from_bytes(bytes: &Self::ByteArray) -> Result<Self, &'static str>
    where
        Self: Sized;
}


/// The `KeyGen` trait is defined to allow trait objects.
pub trait KeyGen {
    /// A public key specific to the chosen security parameter set, e.g., `slh_dsa_shake_128s`, `slh_dsa_sha2_128s` etc
    type PublicKey;
    /// A private (secret) key specific to the chosen security parameter set, e.g., `slh_dsa_shake_128s`, `slh_dsa_sha2_128s` etc
    type PrivateKey;

    /// Generates a public and private key pair specific to this security parameter set. <br>
    /// This function utilizes the OS default random number generator, and makes no (constant)
    /// timing assurances.
    /// # Errors
    /// Returns an error when the random number generator fails; propagates internal errors.
    /// # Examples
    /// ```rust
    /// use fips205::slh_dsa_shake_128s; // Could use any of the twelve security parameter sets.
    /// use fips205::traits::{SerDes, Signer, Verifier};
    /// # use std::error::Error;
    /// #
    /// # fn main() -> Result<(), Box<dyn Error>> {
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
    /// let pk2 = slh_dsa_shake_128s::PublicKey::try_from_bytes(&pk_recv)?;
    /// let v = pk2.try_verify(&msg_recv, &sig_recv, b"context")?;
    /// assert!(v);
    /// # Ok(())
    /// # }
    /// ```
    #[cfg(feature = "default-rng")]
    fn try_keygen() -> Result<(Self::PublicKey, Self::PrivateKey), &'static str> {
        Self::try_keygen_with_rng(&mut OsRng)
    }

    /// Generates a public and private key pair specific to this security parameter set. <br>
    /// This function utilizes a supplied random number generator, and makes no (constant)
    /// timing assurances..
    /// # Errors
    /// Returns an error when the random number generator fails; propagates internal errors.
    /// # Examples
    /// ```rust
    /// use fips205::slh_dsa_shake_128s; // Could use any of the twelve security parameter sets.
    /// use fips205::traits::{SerDes, Signer, Verifier};
    /// # use std::error::Error;
    /// #
    /// # fn main() -> Result<(), Box<dyn Error>> {
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
    /// let pk2 = slh_dsa_shake_128s::PublicKey::try_from_bytes(&pk_recv)?;
    /// let v = pk2.try_verify(&msg_recv, &sig_recv, b"context")?;
    /// assert!(v);
    /// # Ok(())
    /// # }
    /// ```
    fn try_keygen_with_rng(
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Self::PublicKey, Self::PrivateKey), &'static str>;
}


/// The Signer trait is implemented for the `PrivateKey` struct on each of the security parameter sets
pub trait Signer {
    /// The signature is specific to the chosen security parameter set, e.g., `slh_dsa_shake_128s`, `slh_dsa_sha2_128s` etc
    type Signature;

    /// Attempt to sign the given message, returning a digital signature on success, or an error if
    /// something went wrong. This function utilizes the default OS RNG and operates in constant time
    /// with respect to the `PrivateKey` only (not including rejection loop; work in progress).
    ///
    /// # Errors
    /// Returns an error when the random number generator fails; propagates internal errors.
    /// # Examples
    /// ```rust
    /// use fips205::slh_dsa_shake_128s; // Could use any of the twelve security parameter sets.
    /// use fips205::traits::{SerDes, Signer, Verifier};
    /// # use std::error::Error;
    /// #
    /// # fn main() -> Result<(), Box<dyn Error>> {
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
    /// let pk2 = slh_dsa_shake_128s::PublicKey::try_from_bytes(&pk_recv)?;
    /// let v = pk2.try_verify(&msg_recv, &sig_recv, b"context")?;
    /// assert!(v);
    /// # Ok(())
    /// # }
    /// ```
    #[cfg(feature = "default-rng")]
    fn try_sign(
        &self, message: &[u8], ctx: &[u8], randomize: bool,
    ) -> Result<Self::Signature, &'static str> {
        self.try_sign_with_rng(&mut OsRng, message, ctx, randomize)
    }

    /// Attempt to sign the given message, returning a digital signature on success, or an error if
    /// something went wrong. This function utilizes a supplied RNG and operates in constant time
    /// with respect to the `PrivateKey` only (not including rejection loop; work in progress).
    ///
    /// # Errors
    /// Returns an error when the random number generator fails; propagates internal errors.
    /// # Examples
    /// ```rust
    /// use fips205::slh_dsa_shake_128s; // Could use any of the twelve security parameter sets.
    /// use fips205::traits::{SerDes, Signer, Verifier};
    /// # use std::error::Error;
    /// #
    /// # fn main() -> Result<(), Box<dyn Error>> {
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
    /// let pk2 = slh_dsa_shake_128s::PublicKey::try_from_bytes(&pk_recv)?;
    /// let v = pk2.try_verify(&msg_recv, &sig_recv, b"context")?;
    /// assert!(v);
    /// # Ok(())
    /// # }
    /// ```
    fn try_sign_with_rng(
        &self, rng: &mut impl CryptoRngCore, message: &[u8], ctx: &[u8], randomize: bool,
    ) -> Result<Self::Signature, &'static str>;

    /// blah
    /// # Errors
    fn _test_only_raw_sign(
        &self, rng: &mut impl CryptoRngCore, m: &[u8], randomize: bool,
    ) -> Result<Self::Signature, &'static str>;
}


/// The Verifier trait is implemented for `PublicKey` on each of the security parameter sets
pub trait Verifier {
    /// The signature is specific to the chosen security parameter set, e.g., `slh_dsa_shake_128s`, `slh_dsa_sha2_128s` etc
    type Signature;

    /// Verifies a digital signature with respect to a `PublicKey`. This function operates in
    /// variable time.
    ///
    /// # Errors
    /// Returns an error on a malformed signature; propagates internal errors.
    /// # Examples
    /// ```rust
    /// use fips205::slh_dsa_shake_128s; // Could use any of the twelve security parameter sets.
    /// use fips205::traits::{SerDes, Signer, Verifier};
    /// # use std::error::Error;
    /// #
    /// # fn main() -> Result<(), Box<dyn Error>> {
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
    /// let pk2 = slh_dsa_shake_128s::PublicKey::try_from_bytes(&pk_recv)?;
    /// let v = pk2.try_verify(&msg_recv, &sig_recv, b"context")?;
    /// assert!(v);
    /// # Ok(())
    /// # }
    /// ```
    fn try_verify(
        &self, message: &[u8], signature: &Self::Signature, ctx: &[u8],
    ) -> Result<bool, &'static str>;

    /// blah
    /// # Errors
    fn _test_only_raw_verify(
        &self, m: &[u8], sig_bytes: &Self::Signature,
    ) -> Result<bool, &'static str>;
}
