# [IntegrityChain]: FIPS 205 Stateless Hash-Based Digital Signature Standard

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
[![Build Status][build-image]][build-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]

[FIPS 205] Stateless Hash-Based Digital Signature Standard written in pure Rust for server, 
desktop, browser and embedded applications. The source repository includes examples demonstrating 
benchmarking, constant-time statistical measurements, and WASM execution.

This crate implements the FIPS 205 **final/released** standard in pure Rust with minimal and mainstream dependencies,
and without any unsafe code. All twelve (!!) security parameter sets are fully functional. The implementation's
key- and signature-generation functionality operates in constant-time, does not require the standard library, e.g. 
`#[no_std]`, has no heap allocations, e.g. no `alloc` needed, and exposes the `RNG` so it is suitable for the full 
range of applications from server down to the bare-metal. The API is stabilized and the code is heavily biased 
towards safety and correctness; further performance optimizations will be implemented as the standard matures.
This crate will quickly follow any changes to FIPS 205 standard/vectors as they become available.

See <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf> for a full description of the target functionality.

The functionality is extremely simple to use, as demonstrated by the following example.

~~~rust
# use std::error::Error;
#
# fn main() -> Result<(), Box<dyn Error>> {
# #[cfg(all(feature = "slh_dsa_shake_128s", feature = "default-rng"))] {
use fips205::slh_dsa_shake_128s; // Could use any of the twelve security parameter sets.
use fips205::traits::{SerDes, Signer, Verifier};

let msg_bytes = [0u8, 1, 2, 3, 4, 5, 6, 7];

// Generate both public and secret keys. This only fails when the OS rng fails.
let (pk1, sk) = slh_dsa_shake_128s::try_keygen()?;
// Use the secret key to generate a signature. The second parameter is the
// context string (often just an empty &[]), and the last parameter selects
// the preferred hedged variant. This only fails when the OS rng fails.
let sig_bytes = sk.try_sign(&msg_bytes, b"context", true)?;

// Serialize the public key, and send with message and signature bytes. These
// statements model sending byte arrays over the wire.
let (pk_send, msg_send, sig_send) = (pk1.into_bytes(), msg_bytes, sig_bytes);
let (pk_recv, msg_recv, sig_recv) = (pk_send, msg_send, sig_send);

// Deserialize the public key. This only fails on a malformed key.
let pk2 = slh_dsa_shake_128s::PublicKey::try_from_bytes(&pk_recv)?;
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
* `hash_sign` and `hash_verify` take a precomputed digest and a DER-encoded OID
  (`pre_hash` lists the NIST CSOR encodings). The library does not hash the message.
  An empty OID or a digest longer than 1024 bytes is rejected.
* C FFI and a WASM browser demo are described in [`ffi/README.md`](ffi/README.md) and
  [`wasm/README.md`](wasm/README.md).
* Constant-time assurances target the source-code level only, with confirmation via
  manual review/inspection, the embedded target, and the `dudect` dynamic tests.
* Note that FIPS 205 places specific requirements on randomness per section 3.1, hence the exposed `RNG`.
* RNG integration uses **`rand_core` 0.6**. The default features enable `default-rng`
  plus all twelve `slh_dsa_*` parameter sets. That OS RNG path is for hosted
  environments; it will **not** compile on bare-metal targets that lack a `getrandom`
  backend (for example `thumbv7em-none-eabi`). Embedded builds use
  `default-features = false`, the parameter-set feature they need, and
  `keygen_with_seeds` or `*_with_rng`:
  `fips205 = { version = "0.5", default-features = false, features = ["slh_dsa_sha2_128s"] }`.
  Custom generators must implement `CryptoRngCore` from `rand_core` 0.6
  (`CryptoRng` + `RngCore`). This crate re-exports `CryptoRng`, `RngCore`, and
  `RngError`. Key generation and signing call `try_fill_bytes`.
* Requires Rust **1.85** or higher (Debian stable / trixie). The minimum supported Rust version may be changed in the future,
  but it will be done with a minor version bump (when the major version is larger than 0).
* All on-by-default features of this library are covered by `SemVer`.
* The FIPS 205 standard and this software should be considered experimental -- USE AT YOUR OWN RISK!

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
