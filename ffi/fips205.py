"""FIPS 205 (SLH-DSA) Asymmetric Post-Quantum Cryptography

This Python module provides an implementation of FIPS 205, the
Stateless Hash-Based Digital Signature Standard (SLH-DSA). Until
further testing is performed, support is limited to the
`slh_dsa_sha2_128f` security parameter set.


## Example

The following example shows using the standard SLH_DSA algorithm
to sign and verify message byte arrays:

```
from fips205 import slh_dsa_sha2_128f

message = b"this is the message"
(public_key, private_key) = slh_dsa_sha2_128f.keygen()
signature = private_key.sign(message)
check = public_key.verify(message, signature)
assert(check)
```

Public and private keys can be serialized by accessing them as
`bytes`, and deserialized by initializing them with the
appropriate size `bytes` object. Signature are `bytes` objects.

An example demonstrating key generation, signature creation,
serialization and deserialization of the public key, and
signature verification:

```
from fips205 import slh_dsa_sha2_128f

message = b"this is another message"
(public_key, private_key) = slh_dsa_sha2_128f.keygen()
signature = private_key.sign(message)

with open('public.bin', 'wb') as f:
    f.write(bytes(public_key))

from fips205 import PublicKey

with open('public.bin', 'rb') as f:
    pk_bytes = f.read()

pk = PublicKey(pk_bytes, slh_dsa_sha2_128f)
check = pk.verify(message, signature)
```


## Implementation Notes

This is a wrapper around libfips205, built from the Rust fips205-ffi crate.
If that library is not installed in the expected path for libraries on
your system, any attempt to use this module will fail.

Thank you to Daniel Kahn Gillmor for providing an example for FIPS 203.


## See Also

- https://doi.org/10.6028/NIST.FIPS.205.ipd
- https://github.com/integritychain/fips205

"""

__version__ = "0.1.2"
__author__ = "Eric Schorn <eschorn@integritychain.com>"

import ctypes
import enum
from abc import ABC
from typing import Tuple, Any, Callable

lib = ctypes.CDLL("../target/debug/libfips205.so")


class Err(enum.IntEnum):
    OK = 0
    NULL_PTR_ERROR = 1
    SERIALIZATION_ERROR = 2
    DESERIALIZATION_ERROR = 3
    KEYGEN_ERROR = 4
    SIGN_ERROR = 5
    VERIFY_ERROR = 6


class PublicKey:
    """SLH_DSA Public Key

    Serialize this object by asking for it as `bytes`.
    Verify a message + signature by invoking verify() on it.
    """

    def __init__(self, data: bytes, source: Any) -> None:
        """Create SLH_DSA Public Key from bytes, noting its source."""
        if len(data) != source.PK_LEN:
            raise Exception(f"Inconsistent public key source/length")
        self.key = data
        self.source = source

    def __repr__(self) -> str:
        return f"<{self.source.__name__} public key: {self.key.hex()}>"

    def __bytes__(self) -> bytes:
        return bytes(self.key)

    def verify(self, message: bytes, signature: bytes) -> bool:
        """Verify a message and signature pair"""
        if not (isinstance(signature, bytes) and isinstance(message, bytes)):
            raise Exception(f"Signature and message must be bytes")
        if len(signature) != self.source.SIG_LEN:
            raise Exception(f"Inconsistent signature source/length")
        ret = self.source.verify_func(message, len(message), self.key, signature)
        if (ret != Err.OK) & (ret != Err.VERIFY_ERROR):
            raise Exception(f"{self.source.__name__}_verify() returned {ret}")
        return ret == Err.OK


class PrivateKey:
    """SLH_DSA Private Key

    Serialize this object by asking for it as `bytes`.
    Sign a message by invoking sign() on it.
    """

    def __init__(self, data: bytes, source: Any) -> None:
        """Create SLH_DSA Private Key from bytes, noting its source."""
        if len(data) != source.SK_LEN:
            raise Exception(f"Inconsistent private key source/length")
        self.key = data
        self.source = source

    def __repr__(self) -> str:
        return f"<{self.source.__name__} private key: {self.key.hex()}>"

    def __bytes__(self) -> bytes:
        return bytes(self.key)

    def sign(self, message: bytes) -> bytes:
        """Sign a message"""
        if not isinstance(message, bytes):
            raise Exception(f"Message must be bytes")
        signature = bytes([0] * self.source.SIG_LEN)
        ret = self.source.sign_func(message, len(message), self.key, signature)
        if ret != Err.OK:
            raise Exception(f"{self.source.__name__}_sign() returned {ret}")
        return signature


class _Slh_Dsa(ABC):
    """Abstract base class for all SLH-DSA (FIPS 205) parameter sets."""
    PK_LEN: int
    SK_LEN: int
    SIG_LEN: int
    keygen_func: Callable
    sign_func: Callable
    verify_func: Callable

    @classmethod
    def keygen(cls) -> Tuple[PublicKey, PrivateKey]:
        """Generate a pair of Public and Private Keys."""
        (pk, sk) = (bytes([0] * cls.PK_LEN), bytes([0] * cls.SK_LEN))
        ret = cls.keygen_func(pk, sk)
        if ret != Err.OK:
            raise Exception(f"{cls.__name__}_keygen() returned {ret}")
        return PublicKey(pk, cls), PrivateKey(sk, cls)


class slh_dsa_sha2_128f(_Slh_Dsa):
    """slh_dsa_sha2_128f (FIPS 205) implementation."""
    PK_LEN: int = 32
    SK_LEN: int = 64
    SIG_LEN: int = 17088
    keygen_func: Callable = lib.slh_dsa_sha2_128f_keygen
    sign_func: Callable = lib.slh_dsa_sha2_128f_sign
    verify_func: Callable = lib.slh_dsa_sha2_128f_verify


# A quick test can be run from the command line: `python3 fips205.py`
if __name__ == "__main__":
    ppk, ssk = slh_dsa_sha2_128f.keygen()
    sig = ssk.sign(bytes([1, 2, 3]))
    res = ppk.verify(bytes([1, 2, 3]), sig)
    print(f"{res}\n{ppk}\n{ssk}")
