# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.5.0 (in progress)

### Migration from 0.4.x
- Bump the dependency to `fips205 = "0.5"` (this release is **not** API-compatible with
  crates.io `0.4.1`).
- MSRV is now **1.85** (Debian stable / trixie).
- RNG bounds remain `rand_core` 0.6 `CryptoRngCore` (`CryptoRng` + `RngCore`). This
  crate re-exports `CryptoRng`, `RngCore`, and `RngError`.
- Bare-metal / `no_std`: use `default-features = false` plus the desired `slh_dsa_*`
  feature(s); default features pull an OS RNG backend that will not build on many
  embedded targets. Use `keygen_with_seeds` or `*_with_rng`.
- `hash_sign` and `hash_verify` take a precomputed digest and a DER-encoded OID
  (`pre_hash`) instead of the message and `Ph`. The library does not hash the message.
  An empty OID or a digest longer than 1024 bytes is rejected. `Ph` is gone.

### Added
- Re-export `CryptoRng`, `RngCore`, and `RngError` from `rand_core` 0.6

### Fixed
- Clippy pedantic cleanups for current stable (`needless_for_each`, `manual_div_ceil`,
  `unnecessary_semicolon`); CI `clippy` job now installs `dtolnay/rust-toolchain@stable`
  with the clippy component
- Doctests that do not need the OS RNG use `keygen_with_seeds` or a seeded
  `ChaCha8Rng`. README-style examples that call `try_keygen` / `try_sign` are wrapped
  in `default-rng`
- CI `cargo_deny`: bump `EmbarkStudios/cargo-deny-action` to v2; move `deny.toml`
  settings into the `[graph]` / `[output]` tables and drop the removed advisory keys
- CI `cargo_outdated`: exclude `rand_core` (`-x rand_core`) so the job does not fail
  while we stay on the 0.6 line
- Copy-paste: README follows FIPS 205; WASM demo links crates.io `fips205` and the
  final FIPS 205 PDF (section 3.1); fuzz description says SLH-DSA; drop "(draft)"
  from the FFI crate description
- Docs security-parameter link points at `https://docs.rs/fips205/latest/fips205/#modules`

### Changed
- NIST ACVP sample vectors are the ACVP-Server `975de31eb83d` set, gzipped under
  `tests/nist_vectors`, including external pre-hash groups. `FIPS205_NIST_SMOKE=1`
  runs a subset
- Crate and sample versions are **0.5.0** (`fips205`, `fips205-ffi`, `wasm`, `dudect`,
  `fuzz`)
- Raised MSRV to **1.85**; CI MSRV jobs updated accordingly
- Criterion 0.5; pin `textwrap = "=0.16.2"` so Criterion stays buildable without a
  checked-in `Cargo.lock`
- Drop the exact `serde` pin. The NIST harness still uses `serde` with `derive`
- Document that default features (including `default-rng`) are for hosted targets

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
