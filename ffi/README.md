# C shared library for SLH-DSA

This crate is a C ABI for FIPS 205. It exports the four 128-bit parameter sets:

- SLH-DSA-SHA2-128s
- SLH-DSA-SHA2-128f
- SLH-DSA-SHAKE-128s
- SLH-DSA-SHAKE-128f

192-bit and 256-bit sets stay in the Rust crate until a caller asks for them. Shipping all twelve would put signatures of up to about 50 KB into the header.

`fips205.h` is hand-maintained. Error codes and OID tables are `static const`. `keygen`, `sign`, and `hash_sign` (and their deterministic twins) are `static inline` and are not symbols in the shared object. A NULL seed means "draw from the OS RNG". Deterministic signing passes `hedged = 0`; that is not an all-zero `opt_rand`.

The keygen seed is 48 bytes: `sk_seed || sk_prf || pk_seed`. The sign seed is 16 bytes of hedged randomness.

HashSLH-DSA in C takes a digest and a DER OID. The caller hashes. There is no `libmd` dependency; `ffi/python/test/nist.py` covers pre-hash vectors.


# Quick start

~~~
$ cargo build --release -p fips205-ffi
$ make -C ffi/tests check
~~~

`make check` smoke-tests keygen, hedged and deterministic sign, verify, and `get_public_key` for each exported set. It also links two translation units that both include `fips205.h`.


# Shared library names (Linux ELF SONAME)

`cargo build --release -p fips205-ffi` produces **`libfips205.so`** (or `libfips205.dylib` on macOS).

On ELF targets, `build.rs` sets the SONAME to **`libfips205.so.0`**.

| Artifact | Role |
|---|---|
| `libfips205.so` | Link name (`-lfips205`) |
| `libfips205.so.0` | Runtime name the loader looks up |

`ffi/tests/Makefile` creates a local `libfips205.so.0` symlink next to Cargo's output so in-tree runs succeed. On macOS, `build.rs` sets `@rpath/libfips205.dylib` instead.


# Python

The wrapper lives in `ffi/python/`, not `ffi/fips205.py`. From that directory, with the release library just built:

~~~
$ cd ffi/python
$ FIPS205_PYTHON_TESTING_LIBRARY=../../target/release/libfips205.so \
    PYTHONPATH=. python3 test/nist.py
~~~

Importing the module without `libfips205` on the library path raises `OSError` naming that library.
