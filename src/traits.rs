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
    /// println!("Placeholder");
    /// ```
    fn into_bytes(self) -> Self::ByteArray;

    /// Consumes a byte array of fixed-size specific to the struct being deserialized; performs validation
    /// # Errors
    /// Returns an error on malformed input.
    /// # Examples
    /// ```rust
    /// println!("Placeholder");
    /// ```
    fn try_from_bytes(bytes: &Self::ByteArray) -> Result<Self, &'static str>
    where
        Self: Sized;
}


/// The `KeyGen` trait is defined to allow trait objects.
pub trait KeyGen {
    /// A public key specific to the chosen security parameter set, e.g., ml-dsa-44, ml-dsa-65 or ml-dsa-87
    type PublicKey;
    /// A private (secret) key specific to the chosen security parameter set, e.g., ml-dsa-44, ml-dsa-65 or ml-dsa-87
    type PrivateKey;

    /// Generates a public and private key pair specific to this security parameter set. <br>
    /// This function utilizes the OS default random number generator, and makes no (constant)
    /// timing assurances.
    /// # Errors
    /// Returns an error when the random number generator fails; propagates internal errors.
    /// # Examples
    /// ```rust
    /// println!("Placeholder");
    /// ```
    #[cfg(feature = "default-rng")]
    fn try_keygen_vt() -> Result<(Self::PublicKey, Self::PrivateKey), &'static str> {
        Self::try_keygen_with_rng_vt(&mut OsRng)
    }

    /// Generates a public and private key pair specific to this security parameter set. <br>
    /// This function utilizes a supplied random number generator, and makes no (constant)
    /// timing assurances..
    /// # Errors
    /// Returns an error when the random number generator fails; propagates internal errors.
    /// # Examples
    /// ```rust
    /// println!("Placeholder");
    /// ```
    fn try_keygen_with_rng_vt(
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Self::PublicKey, Self::PrivateKey), &'static str>;
}


/// The Signer trait is implemented for the `PrivateKey` struct on each of the security parameter sets
pub trait Signer {
    /// The signature is specific to the chosen security parameter set, e.g., ml-dsa-44, ml-dsa-65 or ml-dsa-87
    type Signature;

    /// Attempt to sign the given message, returning a digital signature on success, or an error if
    /// something went wrong. This function utilizes the default OS RNG and operates in constant time
    /// with respect to the `PrivateKey` only (not including rejection loop; work in progress).
    ///
    /// # Errors
    /// Returns an error when the random number generator fails; propagates internal errors.
    /// # Examples
    /// ```rust
    /// println!("Placeholder");
    /// ```
    #[cfg(feature = "default-rng")]
    fn try_sign_ct(
        &self, message: &[u8], randomize: bool,
    ) -> Result<Self::Signature, &'static str> {
        self.try_sign_with_rng_ct(&mut OsRng, message, randomize)
    }

    /// Attempt to sign the given message, returning a digital signature on success, or an error if
    /// something went wrong. This function utilizes a supplied RNG and operates in constant time
    /// with respect to the `PrivateKey` only (not including rejection loop; work in progress).
    ///
    /// # Errors
    /// Returns an error when the random number generator fails; propagates internal errors.
    /// # Examples
    /// ```rust
    /// println!("Placeholder");
    /// ```
    fn try_sign_with_rng_ct(
        &self, rng: &mut impl CryptoRngCore, message: &[u8], randomize: bool,
    ) -> Result<Self::Signature, &'static str>;
}


/// The Verifier trait is implemented for `PublicKey` on each of the security parameter sets
pub trait Verifier {
    /// The signature is specific to the chosen security parameter set, e.g., ml-dsa-44, ml-dsa-65
    /// or ml-dsa-87
    type Signature;

    /// Verifies a digital signature with respect to a `PublicKey`. This function operates in
    /// variable time.
    ///
    /// # Errors
    /// Returns an error on a malformed signature; propagates internal errors.
    /// # Examples
    /// ```rust
    /// println!("Placeholder");
    /// ```
    fn try_verify_vt(
        &self, message: &[u8], signature: &Self::Signature,
    ) -> Result<bool, &'static str>;
}
