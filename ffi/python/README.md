FIPS 205 (SLH-DSA) hash-based digital signatures

This Python module provides an implementation of FIPS 205, the
Stateless Hash-Based Digital Signature Standard.

The C shared library exports the four 128-bit parameter sets.
192-bit and 256-bit sets are Rust-only in this release.

## Example

```
from fips205 import SLH_DSA_SHA2_128S

message = b"this is a test"
context = b""
(public_key, private_key) = SLH_DSA_SHA2_128S.keygen()
sig = private_key.sign(message, context)
assert public_key.verify(sig, message, context)
```

Key generation can be deterministic. The seed is 48 bytes:
`sk_seed || sk_prf || pk_seed`, 16 bytes each.

```
from fips205 import SLH_DSA_SHA2_128S, Seed

seed = Seed(b"\x00" * SLH_DSA_SHA2_128S.KEYGEN_SEED_SIZE)
(public_key, private_key) = SLH_DSA_SHA2_128S.keygen(seed)
```

Public and private keys serialize as `bytes`. A signature is `bytes`.
Pass the parameter set when deserializing: SHA2-128s and SHAKE-128s
are the same length, and so are the two 128f sets.

```
from fips205 import SLH_DSA_SHA2_128S, PublicKey, PrivateKey

message = b"this is a test"
context = b"abc"
(public_key, private_key) = SLH_DSA_SHA2_128S.keygen()
signature = private_key.sign(message, context)
with open("pub.bin", "wb") as pub_out:
    pub_out.write(bytes(public_key))
with open("priv.bin", "wb") as priv_out:
    priv_out.write(bytes(private_key))
with open("pub.bin", "rb") as pub_in:
    pub = PublicKey(SLH_DSA_SHA2_128S, pub_in.read())
with open("priv.bin", "rb") as priv_in:
    priv = PrivateKey(SLH_DSA_SHA2_128S, priv_in.read())
assert pub.verify(signature, message, context)
assert pub.verify(priv.sign(message, context), message, context)
```

Hedged signing is the default. `sign(..., hedged=False)` is the
deterministic variant. Pass 16 bytes as `hedged` to supply `opt_rand`.

HashSLH-DSA takes a digest and a DER OID. `HASH_OIDS` maps NIST
hyphenated names such as `"SHA2-256"` onto those bytes. This module
does not hash the message.

## Implementation Notes

This is a wrapper around libfips205, built from the Rust fips205-ffi crate.

If that library is not installed in the expected path for libraries on
your system, importing this module will fail. For in-tree tests, set
`FIPS205_PYTHON_TESTING_LIBRARY` to the built `libfips205.so`.

## See Also

- https://csrc.nist.gov/pubs/fips/205/final
- https://github.com/integritychain/fips205

## Bug Reporting

Please report issues at https://github.com/integritychain/fips205/issues
