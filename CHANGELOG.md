# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.5.0 (unreleased)

### Migration from 0.4.x
- MSRV is 1.85 (was 1.70).
- `Ph` is removed. `try_hash_sign` and `hash_verify` take the caller's digest and a DER-encoded OID (see `pre_hash`) in place of the message. For a `pre_hash` OID the digest must be that function's full output (SHAKE128: 32 bytes, SHAKE256: 64 bytes). A digest of the wrong length, a non-DER OID, or a digest over 1024 bytes is an error on sign and `false` on verify.
- Cargo features use hyphens: `slh-dsa-sha2-128s`, not `slh_dsa_sha2_128s`, and likewise for all twelve sets. Module names are unchanged.
- `KeyGen::keygen_with_seeds` is renamed `keygen_from_seed`.
- `SerDes::try_from_bytes` takes the byte array by value: write `try_from_bytes(bytes)`, not `try_from_bytes(&bytes)`.

### Added
- `libfips205`, a C library for the four 128-bit sets including HashSLH-DSA, and Python bindings in `ffi/python`.
- `CryptoRng`, `RngCore` and `RngError` are re-exported from `rand_core` 0.6.

### Changed
- Key generation and signing are constant-time. Signatures are unchanged.
- Key generation and signing zeroize their seeds, randomness and secret intermediate values.

### Removed
- Deprecated `_test_only_raw_sign` and `_test_only_raw_verify`. Test hooks are now behind the `acvp-internal` feature, which is not for use in applications.

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
