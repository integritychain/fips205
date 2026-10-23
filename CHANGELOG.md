# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.5.0 (2026-10-23)

### Migration from 0.4.x
- MSRV is 1.85 (was 1.70).
- `Ph` is removed. `try_hash_sign`, `try_hash_sign_with_rng` and `hash_verify` take a digest and a DER-encoded OID (see `pre_hash`) instead of the message. A digest of the wrong length for a `pre_hash` OID (SHAKE128: 32 bytes, SHAKE256: 64), a digest over 1024 bytes, or a malformed OID is an error on sign and `false` on verify.
- Cargo features use hyphens: `slh-dsa-sha2-128s`, not `slh_dsa_sha2_128s`, for all twelve sets. Module names are unchanged.
- `KeyGen::keygen_with_seeds` is renamed `keygen_from_seed`. A seed of the wrong length fails to build (0.4 panicked at run time).
- `SerDes::try_from_bytes` takes the byte array by value: `try_from_bytes(bytes)`, not `try_from_bytes(&bytes)`.
- `KG` no longer implements `Zeroize` or `ZeroizeOnDrop`.

### Added
- `libfips205` (crate `fips205-ffi`): a C library and Python bindings for the four 128-bit sets, including HashSLH-DSA.
- `pre_hash`: DER-encoded OIDs of the pre-hash functions, for `try_hash_sign` and `hash_verify`.
- `CryptoRng`, `RngCore` and `RngError` are re-exported from `rand_core` 0.6.

### Changed
- `Signer::get_public_key` is `#[must_use]`.
- Signing time no longer varies with the message digest: every signature makes the same number of hash calls. Signatures are unchanged.
- Key generation and signing zeroize their randomness and secret intermediate values, best effort: copies of keys that are moved or passed by value can remain on the stack.
- Building the crate itself, as distributions do, no longer fails on new compiler warnings or with no parameter-set feature.

### Removed
- Deprecated `_test_only_raw_sign` and `_test_only_raw_verify`. Test hooks are behind the `acvp-internal` feature, which is not for applications.

## 0.4.1 (2024-12-22)

- Added keygen with seeds for deterministic keygen
- Added two fuzzing harnesses (still some work to go)

## 0.4.0 (2024-10-04)

- Updated to FIPS 205 final spec

## 0.1.2 (2024-03-15)

- Internal improvements, removed dependency on generic-array, MSRV at 1.70
- Supporting examples for benchmarking, CT measurements, WASM development, 
  C FFI, and Python bindings
- Additional testcases

## 0.1.1 (2024-02-14)

- Initial release
