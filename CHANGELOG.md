# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.5.0 (in progress)

### Migration from 0.4.x
- Not API-compatible with 0.4.1. Depend on `fips205 = "0.5"`.
- MSRV is **1.85**.
- `Ph` is gone. `hash_sign` and `hash_verify` take a precomputed digest and a DER-encoded OID (`pre_hash`). This crate does not hash the message. An empty OID or a digest longer than 1024 bytes is rejected.
- `SerDes::try_from_bytes` takes the byte array by value, as in `fips203` and `fips204`. Write `PublicKey::try_from_bytes(bytes)`, not `try_from_bytes(&bytes)`. The arrays are `Copy`, so the caller keeps its copy.
- Cargo features use hyphens, as in `fips203` and `fips204`. Write `slh-dsa-sha2-128s`, not `slh_dsa_sha2_128s`, and likewise for all twelve sets. Module names such as `fips205::slh_dsa_sha2_128s` are unchanged.
- `KeyGen::keygen_with_seeds` is renamed `keygen_from_seed`, as in `fips203`, `fips204` and this crate's C API. It takes the same three seeds.
- RNG stays `rand_core` 0.6. `CryptoRng`, `RngCore`, and `RngError` are re-exported.
- Default features enable the OS RNG and all twelve parameter sets. That does not build on bare metal. Use `default-features = false`, one `slh-dsa-*` feature, and `keygen_from_seed` or `*_with_rng`.

### Added
- `libfips205` for the four 128-bit sets, including HashSLH-DSA, and Python bindings in `ffi/python`. The 192- and 256-bit sets stay Rust-only (expanded upon request).

### Changed
- The constant-time claim covers the secret seed. WOTS and FORS lengths follow the message digest, and verify uses public data.

### Removed
- Deprecated `_test_only_raw_sign` and `_test_only_raw_verify`.

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
