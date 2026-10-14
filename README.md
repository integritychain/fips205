# [IntegrityChain]: FIPS 205 Stateless Hash-Based Digital Signature Standard

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
[![Build Status][build-image]][build-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]

[FIPS 205] Stateless Hash-Based Digital Signature Standard written in pure Rust for server, desktop, browser and
embedded applications. The source repository includes examples demonstrating benchmarking, code provenance,
constant-time statistical measurements, a fuzzing harness, WASM execution, a C FFI shared library and Python bindings.

This crate implements the released FIPS 205 standard in pure Rust with minimal and mainstream dependencies, and without
any unsafe code. All twelve security parameter sets are fully functional and tested. Key generation and signing are
constant-time: every branch, loop bound and memory index depends only on public data, and each signature makes the
same number of hash calls for its parameter set, whatever the key, message or randomness. The crate does not require
the standard library (it is `#![no_std]`), makes no heap allocations (no `alloc` needed), and exposes the `RNG`, so it
suits the full range of applications from server down to bare metal. The API is stabilized, and the code is heavily
biased towards safety and correctness.

See <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf> for a full description of the target functionality.

The functionality is extremely simple to use, as demonstrated by the following example.

~~~rust
# use std::error::Error;
#
# fn main() -> Result<(), Box<dyn Error>> {
# #[cfg(all(feature = "slh-dsa-shake-128s", feature = "default-rng"))] {
use fips205::slh_dsa_shake_128s; // Could use any of the twelve security parameter sets.
use fips205::traits::{SerDes, Signer, Verifier};

let msg_bytes = [0u8, 1, 2, 3, 4, 5, 6, 7];

// Generate both public and secret keys. This only fails when the OS rng fails.
let (pk1, sk) = slh_dsa_shake_128s::try_keygen()?;
// Use the secret key to generate a signature. The second parameter is the
// context string (often just an empty &[]), and the last parameter selects
// the preferred hedged variant. This fails when the OS rng fails or the context is longer than 255 bytes.
let sig_bytes = sk.try_sign(&msg_bytes, b"context", true)?;

// Serialize the public key, and send with message and signature bytes. These
// statements model sending byte arrays over the wire.
let (pk_send, msg_send, sig_send) = (pk1.into_bytes(), msg_bytes, sig_bytes);
let (pk_recv, msg_recv, sig_recv) = (pk_send, msg_send, sig_send);

// A public key of the right length always decodes.
let pk2 = slh_dsa_shake_128s::PublicKey::try_from_bytes(pk_recv)?;
// Use the public key to verify the msg signature
let v = pk2.verify(&msg_recv, &sig_recv, b"context");
assert!(v);
# }
# Ok(())
# }
~~~

The Rust [Documentation][docs-link] lives under each **Module** corresponding to the desired
[security parameter][docs-modules].

## Notes

* This crate is fully functional and corresponds to the final released FIPS 205 (August 13, 2024).
* Constant-time: key generation and signing never branch, loop or index memory on secret data
  (`SK.seed`, `SK.prf`, `opt_rand`, and the FORS and WOTS+ secret values derived from them). Control
  flow and memory access follow only public data: the parameter set, the message and context
  lengths, the `hedged` flag, and the message digest, tree indices and WOTS+ digits that the
  signature reveals. For each parameter set, key generation and signing always make the same
  number of calls to each hash function; only hashing the message and context takes longer as
  they grow. Checked by source review, by counting hash calls in all twelve parameter sets,
  and by the [`dudect`](dudect/README.md) measurements. The claim is at the source level: the
  compiler and CPU are trusted not to add secret-dependent timing, and the caller's RNG is
  outside it. Verify uses only public data and makes no constant-time claim.
* FIPS 205 places specific requirements on randomness (section 3.1), hence the exposed `RNG`. RNG
  integration uses **`rand_core` 0.6**: custom generators implement `CryptoRngCore` (`CryptoRng` +
  `RngCore`), which this crate re-exports along with `RngError`. Key generation and signing call
  `try_fill_bytes`, so handle its error or use the seed-based functions.
* The default features enable `default-rng` plus all twelve parameter sets. That OS RNG path is
  for hosted environments; it will **not** compile on bare-metal targets that lack a `getrandom`
  backend (for example `thumbv7em-none-eabi`). Embedded builds use `default-features = false`,
  the parameter-set feature they need, and the seed-based functions or `*_with_rng`:
  `fips205 = { version = "0.5", default-features = false, features = ["slh-dsa-sha2-128s"] }`.
* `hash_sign` and `hash_verify` (HashSLH-DSA) take a precomputed digest and a DER-encoded OID
  (`pre_hash` lists the NIST CSOR encodings). The library does not hash the message. An empty
  OID or a digest longer than 1024 bytes is rejected.
* Test vectors: the NIST ACVP keyGen, sigGen and sigVer vectors (including HashSLH-DSA) and the
  [SLotH](https://github.com/slh-dsa/sloth) known-answer files, regenerated and checked by hash,
  run in the test suite, and the Python bindings apply the ACVP files for the four 128-bit sets
  through the C ABI. The vector files stay in the repository; the published crate omits them.
* A C shared library (`libfips205`) for the four 128-bit sets, including HashSLH-DSA, with Python
  bindings, and a WASM browser demo, are described in [`ffi/README.md`](ffi/README.md) and
  [`wasm/README.md`](wasm/README.md).
* Requires Rust **1.85** or higher (Debian stable, trixie). The minimum supported Rust version may
  change in the future, but only with a minor version bump (once the major version is above 0).
* All on-by-default features of this library are covered by `SemVer`.

## License

Contents are licensed under either the [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
or [MIT license](http://opensource.org/licenses/MIT) at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as
defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.

[//]: # (badges)

[crate-image]: https://img.shields.io/crates/v/fips205
[crate-link]: https://crates.io/crates/fips205
[docs-image]: https://docs.rs/fips205/badge.svg
[docs-link]: https://docs.rs/fips205/
[docs-modules]: https://docs.rs/fips205/latest/fips205/#modules
[build-image]: https://github.com/integritychain/fips205/workflows/test/badge.svg
[build-link]: https://github.com/integritychain/fips205/actions?query=workflow%3Atest
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.85+-blue.svg

[//]: # (general links)

[IntegrityChain]: https://github.com/integritychain/
[FIPS 205]: https://csrc.nist.gov/pubs/fips/205/final
