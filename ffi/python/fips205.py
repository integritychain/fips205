"""FIPS 205 (SLH-DSA) hash-based digital signatures

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

seed = Seed(b"\\x00" * SLH_DSA_SHA2_128S.KEYGEN_SEED_SIZE)
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
hyphenated names such as `"SHA2-256"`, and short names such as
`"SHA256"`, onto those bytes. This module does not hash the message.

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
"""

from __future__ import annotations

__version__ = "0.5.0"
__author__ = "Eric Schorn <eschorn@integritychain.com>"
__all__ = [
    "SLH_DSA_SHA2_128S",
    "SLH_DSA_SHA2_128F",
    "SLH_DSA_SHAKE_128S",
    "SLH_DSA_SHAKE_128F",
    "PublicKey",
    "PrivateKey",
    "Seed",
    "HASH_OIDS",
]

import ctypes
import ctypes.util
import enum
from abc import ABC
from os import environ
from typing import Any, Dict, Optional, Tuple, Type, Union


# NIST hyphenated names used by ACVP, mapped to DER OIDs (tag and length included).
# hash_sign and hash_verify accept one of these names, or the raw OID bytes.
HASH_OIDS: Dict[str, bytes] = {
    "SHA2-224": b"\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x04",
    "SHA2-256": b"\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01",
    "SHA2-384": b"\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x02",
    "SHA2-512": b"\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03",
    "SHA2-512/224": b"\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x05",
    "SHA2-512/256": b"\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x06",
    "SHA3-224": b"\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x07",
    "SHA3-256": b"\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x08",
    "SHA3-384": b"\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x09",
    "SHA3-512": b"\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x0a",
    "SHAKE-128": b"\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x0b",
    "SHAKE-256": b"\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x0c",
}
# Names that are not the ACVP spelling, kept as lookups on the same bytes.
for _short, _long in (
    ("SHA224", "SHA2-224"),
    ("SHA256", "SHA2-256"),
    ("SHA384", "SHA2-384"),
    ("SHA512", "SHA2-512"),
    ("SHA512/224", "SHA2-512/224"),
    ("SHA512/256", "SHA2-512/256"),
):
    HASH_OIDS[_short] = HASH_OIDS[_long]


class _KeygenSeed(ctypes.Structure):
    _fields_ = [("data", ctypes.c_uint8 * 48)]


class _SignSeed(ctypes.Structure):
    _fields_ = [("data", ctypes.c_uint8 * 16)]


class Err(enum.IntEnum):
    OK = 0
    NULL_PTR_ERROR = 1
    SERIALIZATION_ERROR = 2
    DESERIALIZATION_ERROR = 3
    KEYGEN_ERROR = 4
    SIGN_ERROR = 5
    VERIFICATION_ERROR = 6
    VERIFICATION_FAILURE = 7


def _buf(data: bytes) -> Tuple[Optional[Any], int]:
    """Pointer and length that keep embedded NUL bytes."""
    if len(data) == 0:
        return None, 0
    raw = (ctypes.c_uint8 * len(data)).from_buffer_copy(data)
    return raw, len(data)


def _as_ptr(raw: Optional[Any]) -> Optional[Any]:
    if raw is None:
        return None
    return ctypes.cast(raw, ctypes.POINTER(ctypes.c_uint8))


class Seed:
    """48-byte SLH-DSA keygen seed: sk_seed || sk_prf || pk_seed."""

    def __init__(self, data: Optional[bytes] = None) -> None:
        """If initialized with None, the seed is drawn from the OS."""
        self._seed = _KeygenSeed()
        if data is None:
            err = Err(_FFI.lib.slh_dsa_populate_seed(ctypes.byref(self._seed)))
            if err is not Err.OK:
                raise Exception(f"slh_dsa_populate_seed() returned {err} ({err.name})")
            return
        if len(data) != len(self._seed.data):
            raise ValueError(f"Expected {len(self._seed.data)} bytes, got {len(data)}.")
        for i, octet in enumerate(data):
            self._seed.data[i] = octet

    def __repr__(self) -> str:
        return "<SLH-DSA keygen seed>"

    def __bytes__(self) -> bytes:
        return bytes(self._seed.data)


class PublicKey:
    """SLH-DSA public key for one parameter set.

    Serialize by asking for this object as `bytes`.
    """

    def __init__(self, param: Type["SLH_DSA"], data: Optional[bytes] = None) -> None:
        self._param = param
        self._ffi = _FFI.for_param(param)
        self._pubkey = self._ffi["PublicKey"]()
        if data is not None:
            self._set(data)

    def __repr__(self) -> str:
        return f"<{self._param.name} public key>"

    def __bytes__(self) -> bytes:
        return bytes(self._pubkey.data)

    def _set(self, data: bytes) -> None:
        if len(data) != len(self._pubkey.data):
            raise ValueError(f"Expected {len(self._pubkey.data)} bytes, got {len(data)}")
        for i, octet in enumerate(data):
            self._pubkey.data[i] = octet

    def verify(self, sig: bytes, message: bytes, context: bytes = b"") -> bool:
        """Verify `sig` over `message` in `context`."""
        if len(sig) != self._param.SIG_SIZE:
            return False
        sig_param = self._ffi["Signature"]()
        for i, octet in enumerate(sig):
            sig_param.data[i] = octet
        msg, msg_len = _buf(message)
        ctx, ctx_len = _buf(context)
        ret = Err(
            self._ffi["verify"](
                ctypes.byref(self._pubkey),
                ctypes.byref(sig_param),
                _as_ptr(msg),
                msg_len,
                _as_ptr(ctx),
                ctx_len,
            )
        )
        if ret not in {Err.OK, Err.VERIFICATION_FAILURE}:
            raise Exception(f"{self._param.name}_verify() returned {ret} ({ret.name})")
        return ret == Err.OK

    def hash_verify(
        self,
        sig: bytes,
        digest: bytes,
        hash_oid: Union[bytes, str],
        context: bytes = b"",
    ) -> bool:
        """Verify a HashSLH-DSA signature over `digest`.

        `hash_oid` is a DER OID, or a name in `HASH_OIDS`. This function
        does not hash `digest` again.
        """
        if isinstance(hash_oid, str):
            hash_oid = HASH_OIDS[hash_oid]
        if len(sig) != self._param.SIG_SIZE:
            return False
        sig_param = self._ffi["Signature"]()
        for i, octet in enumerate(sig):
            sig_param.data[i] = octet
        dig, dig_len = _buf(digest)
        ctx, ctx_len = _buf(context)
        oid, oid_len = _buf(hash_oid)
        ret = Err(
            self._ffi["hash_verify"](
                ctypes.byref(self._pubkey),
                ctypes.byref(sig_param),
                _as_ptr(dig),
                dig_len,
                _as_ptr(ctx),
                ctx_len,
                _as_ptr(oid),
                oid_len,
            )
        )
        if ret not in {Err.OK, Err.VERIFICATION_FAILURE}:
            raise Exception(f"{self._param.name}_hash_verify() returned {ret} ({ret.name})")
        return ret == Err.OK


class PrivateKey:
    """SLH-DSA private key for one parameter set."""

    def __init__(self, param: Type["SLH_DSA"], data: Optional[bytes] = None) -> None:
        self._param = param
        self._ffi = _FFI.for_param(param)
        self._privkey = self._ffi["PrivateKey"]()
        if data is not None:
            self._set(data)

    def __repr__(self) -> str:
        return f"<{self._param.name} private key>"

    def __bytes__(self) -> bytes:
        return bytes(self._privkey.data)

    def _set(self, data: bytes) -> None:
        if len(data) != len(self._privkey.data):
            raise ValueError(f"Expected {len(self._privkey.data)} bytes, got {len(data)}")
        for i, octet in enumerate(data):
            self._privkey.data[i] = octet

    def public_key(self) -> PublicKey:
        """Derive the public key from this private key."""
        pub = PublicKey(self._param)
        ret = Err(
            self._ffi["get_public_key"](ctypes.byref(self._privkey), ctypes.byref(pub._pubkey))
        )
        if ret is not Err.OK:
            raise Exception(f"{self._param.name}_get_public_key() returned {ret} ({ret.name})")
        return pub

    def sign(
        self,
        message: bytes,
        context: bytes = b"",
        hedged: Union[bool, bytes] = True,
    ) -> bytes:
        """Sign `message` in `context`.

        `hedged=True` draws `opt_rand` from the OS. `hedged=False` is the
        deterministic variant. `hedged` as 16 bytes is that `opt_rand`.
        """
        return self._sign("sign", message, None, context, hedged)

    def hash_sign(
        self,
        digest: bytes,
        hash_oid: Union[bytes, str],
        context: bytes = b"",
        hedged: Union[bool, bytes] = True,
    ) -> bytes:
        """Sign a precomputed digest.

        `hash_oid` is a DER OID, or a name in `HASH_OIDS`. This function
        does not hash `digest` again.
        """
        if isinstance(hash_oid, str):
            hash_oid = HASH_OIDS[hash_oid]
        return self._sign("hash_sign", digest, hash_oid, context, hedged)

    def _sign(
        self,
        which: str,
        payload: bytes,
        hash_oid: Optional[bytes],
        context: bytes,
        hedged: Union[bool, bytes],
    ) -> bytes:
        sig = self._ffi["Signature"]()
        seed: Optional[_SignSeed] = None
        hedged_flag = 1
        if hedged is False:
            hedged_flag = 0
        elif hedged is True:
            hedged_flag = 1
        elif isinstance(hedged, bytes):
            if len(hedged) != self._param.SIGN_SEED_SIZE:
                raise ValueError(
                    f"Expected {self._param.SIGN_SEED_SIZE} sign-seed bytes, got {len(hedged)}"
                )
            seed = _SignSeed()
            for i, octet in enumerate(hedged):
                seed.data[i] = octet
        else:
            raise TypeError(f"hedged must be bool or bytes, got {type(hedged)}")
        body, body_len = _buf(payload)
        ctx, ctx_len = _buf(context)
        args = [
            ctypes.byref(self._privkey),
            _as_ptr(body),
            body_len,
            _as_ptr(ctx),
            ctx_len,
        ]
        if hash_oid is not None:
            oid, oid_len = _buf(hash_oid)
            args.extend([_as_ptr(oid), oid_len])
        args.extend(
            [
                None if seed is None else ctypes.byref(seed),
                hedged_flag,
                ctypes.byref(sig),
            ]
        )
        ret = Err(self._ffi[which](*args))
        if ret is not Err.OK:
            raise Exception(f"{self._param.name}_{which}() returned {ret} ({ret.name})")
        return bytes(sig.data)


class _FFI:
    testlibpath = environ.get("FIPS205_PYTHON_TESTING_LIBRARY", None)
    if testlibpath:
        lib = ctypes.CDLL(testlibpath)
    else:
        libname = ctypes.util.find_library("fips205")
        if libname is None:
            raise OSError(
                "libfips205 shared library not found. Install it, or set "
                "FIPS205_PYTHON_TESTING_LIBRARY to the path of libfips205.so "
                "for in-tree tests."
            )
        lib = ctypes.CDLL(libname)

    lib.slh_dsa_populate_seed.argtypes = [ctypes.POINTER(_KeygenSeed)]
    lib.slh_dsa_populate_seed.restype = ctypes.c_uint8

    cache: Dict[str, Dict[str, Any]] = {}

    @classmethod
    def for_param(cls, param: Type["SLH_DSA"]) -> Dict[str, Any]:
        if param.name in cls.cache:
            return cls.cache[param.name]

        class _PublicKey(ctypes.Structure):
            _fields_ = [("data", ctypes.c_uint8 * param.PUBKEY_SIZE)]

        class _PrivateKey(ctypes.Structure):
            _fields_ = [("data", ctypes.c_uint8 * param.PRIVKEY_SIZE)]

        class _Signature(ctypes.Structure):
            _fields_ = [("data", ctypes.c_uint8 * param.SIG_SIZE)]

        prefix = param.name
        ffi: Dict[str, Any] = {}
        ffi["PublicKey"] = _PublicKey
        ffi["PrivateKey"] = _PrivateKey
        ffi["Signature"] = _Signature

        ffi["keygen_from_seed"] = cls.lib[f"{prefix}_keygen_from_seed"]
        ffi["keygen_from_seed"].argtypes = [
            ctypes.POINTER(_KeygenSeed),
            ctypes.POINTER(_PublicKey),
            ctypes.POINTER(_PrivateKey),
        ]
        ffi["keygen_from_seed"].restype = ctypes.c_uint8

        ffi["get_public_key"] = cls.lib[f"{prefix}_get_public_key"]
        ffi["get_public_key"].argtypes = [
            ctypes.POINTER(_PrivateKey),
            ctypes.POINTER(_PublicKey),
        ]
        ffi["get_public_key"].restype = ctypes.c_uint8

        ffi["sign"] = cls.lib[f"{prefix}_sign_with_seed"]
        ffi["sign"].argtypes = [
            ctypes.POINTER(_PrivateKey),
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.c_size_t,
            ctypes.POINTER(_SignSeed),
            ctypes.c_uint8,
            ctypes.POINTER(_Signature),
        ]
        ffi["sign"].restype = ctypes.c_uint8

        ffi["hash_sign"] = cls.lib[f"{prefix}_hash_sign_with_seed"]
        ffi["hash_sign"].argtypes = [
            ctypes.POINTER(_PrivateKey),
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.c_size_t,
            ctypes.POINTER(_SignSeed),
            ctypes.c_uint8,
            ctypes.POINTER(_Signature),
        ]
        ffi["hash_sign"].restype = ctypes.c_uint8

        ffi["verify"] = cls.lib[f"{prefix}_verify"]
        ffi["verify"].argtypes = [
            ctypes.POINTER(_PublicKey),
            ctypes.POINTER(_Signature),
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.c_size_t,
        ]
        ffi["verify"].restype = ctypes.c_uint8

        ffi["hash_verify"] = cls.lib[f"{prefix}_hash_verify"]
        ffi["hash_verify"].argtypes = [
            ctypes.POINTER(_PublicKey),
            ctypes.POINTER(_Signature),
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.c_size_t,
        ]
        ffi["hash_verify"].restype = ctypes.c_uint8

        cls.cache[param.name] = ffi
        return ffi


class SLH_DSA(ABC):
    """One exported 128-bit SLH-DSA parameter set."""

    name: str
    PUBKEY_SIZE: int
    PRIVKEY_SIZE: int
    SIG_SIZE: int
    KEYGEN_SEED_SIZE: int = 48
    SIGN_SEED_SIZE: int = 16

    @classmethod
    def keygen(cls, seed: Optional[Seed] = None) -> Tuple[PublicKey, PrivateKey]:
        """Generate a key pair. A seed makes generation deterministic."""
        pub = PublicKey(cls)
        priv = PrivateKey(cls)
        ffi = _FFI.for_param(cls)
        ret = Err(
            ffi["keygen_from_seed"](
                None if seed is None else ctypes.byref(seed._seed),
                ctypes.byref(pub._pubkey),
                ctypes.byref(priv._privkey),
            )
        )
        if ret is not Err.OK:
            raise Exception(f"{cls.name}_keygen_from_seed() returned {ret} ({ret.name})")
        return pub, priv


class SLH_DSA_SHA2_128S(SLH_DSA):
    """SLH-DSA-SHA2-128s."""

    name = "slh_dsa_sha2_128s"
    PUBKEY_SIZE = 32
    PRIVKEY_SIZE = 64
    SIG_SIZE = 7856


class SLH_DSA_SHA2_128F(SLH_DSA):
    """SLH-DSA-SHA2-128f."""

    name = "slh_dsa_sha2_128f"
    PUBKEY_SIZE = 32
    PRIVKEY_SIZE = 64
    SIG_SIZE = 17088


class SLH_DSA_SHAKE_128S(SLH_DSA):
    """SLH-DSA-SHAKE-128s."""

    name = "slh_dsa_shake_128s"
    PUBKEY_SIZE = 32
    PRIVKEY_SIZE = 64
    SIG_SIZE = 7856


class SLH_DSA_SHAKE_128F(SLH_DSA):
    """SLH-DSA-SHAKE-128f."""

    name = "slh_dsa_shake_128f"
    PUBKEY_SIZE = 32
    PRIVKEY_SIZE = 64
    SIG_SIZE = 17088
