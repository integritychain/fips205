#!/usr/bin/python3
"""External NIST vectors for the four 128-bit sets.

From the ffi/python/ directory:

FIPS205_PYTHON_TESTING_LIBRARY=../../target/debug/libfips205.so PYTHONPATH=. python3 test/nist.py
"""

from __future__ import annotations

import gzip
import hashlib
import json
import os
from binascii import a2b_hex, b2a_hex
import fips205

EXPORTED = {
    "SLH-DSA-SHA2-128s": fips205.SLH_DSA_SHA2_128S,
    "SLH-DSA-SHA2-128f": fips205.SLH_DSA_SHA2_128F,
    "SLH-DSA-SHAKE-128s": fips205.SLH_DSA_SHAKE_128S,
    "SLH-DSA-SHAKE-128f": fips205.SLH_DSA_SHAKE_128F,
}

_DIGESTS = {
    "SHA2-224": ("sha224", None),
    "SHA2-256": ("sha256", None),
    "SHA2-384": ("sha384", None),
    "SHA2-512": ("sha512", None),
    "SHA2-512/224": ("sha512_224", None),
    "SHA2-512/256": ("sha512_256", None),
    "SHA3-224": ("sha3_224", None),
    "SHA3-256": ("sha3_256", None),
    "SHA3-384": ("sha3_384", None),
    "SHA3-512": ("sha3_512", None),
    "SHAKE-128": ("shake_128", 32),
    "SHAKE-256": ("shake_256", 64),
}


def digest_message(alg: str, message: bytes) -> bytes:
    name, length = _DIGESTS[alg]
    hasher = hashlib.new(name)
    hasher.update(message)
    if length is None:
        return hasher.digest()
    return hasher.digest(length)


def vector_path(mode: str) -> str:
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(
        here,
        "..",
        "..",
        "..",
        "tests",
        "nist_vectors",
        f"SLH-DSA-{mode}-FIPS205",
        "internalProjection.json.gz",
    )


def load(mode: str) -> dict:
    with gzip.open(vector_path(mode), "rt") as handle:
        document = json.load(handle)
    assert document["vsId"] == 53
    assert document["algorithm"] == "SLH-DSA"
    assert document["revision"] == "FIPS205"
    assert document["isSample"] is True
    assert document["mode"] == mode
    return document


def hedged_arg(group: dict, test: dict) -> object:
    if group["deterministic"]:
        return False
    rnd = a2b_hex(test["additionalRandomness"])
    return rnd


def run_keygen() -> None:
    passed = 0
    skipped = 0
    for group in load("keyGen")["testGroups"]:
        param = EXPORTED.get(group["parameterSet"])
        if param is None:
            skipped += len(group["tests"])
            continue
        for test in group["tests"]:
            seed = fips205.Seed(
                a2b_hex(test["skSeed"]) + a2b_hex(test["skPrf"]) + a2b_hex(test["pkSeed"])
            )
            pub, priv = param.keygen(seed)
            loc = f"{group['parameterSet']} tgId={group['tgId']} tcId={test['tcId']}"
            if bytes(pub) != a2b_hex(test["pk"]):
                raise Exception(f"{loc} pk got {b2a_hex(bytes(pub))!r}")
            if bytes(priv) != a2b_hex(test["sk"]):
                raise Exception(f"{loc} sk got {b2a_hex(bytes(priv))!r}")
            passed += 1
    print(f"Passed {passed} keyGen tests ({skipped} skipped)")


def run_siggen() -> None:
    passed = 0
    skipped = 0
    for group in load("sigGen")["testGroups"]:
        param = EXPORTED.get(group["parameterSet"])
        external = group["signatureInterface"] == "external"
        if param is None or not external:
            skipped += len(group["tests"])
            continue
        pre = group["preHash"]
        for test in group["tests"]:
            priv = fips205.PrivateKey(param, a2b_hex(test["sk"]))
            message = a2b_hex(test["message"])
            context = a2b_hex(test["context"])
            hedged = hedged_arg(group, test)
            if pre == "preHash":
                digest = digest_message(test["hashAlg"], message)
                sig = priv.hash_sign(digest, test["hashAlg"], context, hedged)
            elif pre == "pure":
                sig = priv.sign(message, context, hedged)
            else:
                raise Exception(f"unexpected external preHash {pre}")
            loc = f"{group['parameterSet']} tgId={group['tgId']} tcId={test['tcId']}"
            if sig != a2b_hex(test["signature"]):
                raise Exception(f"{loc} sigGen mismatch")
            passed += 1
    print(f"Passed {passed} sigGen tests ({skipped} skipped)")


def run_sigver() -> None:
    passed = 0
    skipped = 0
    for group in load("sigVer")["testGroups"]:
        param = EXPORTED.get(group["parameterSet"])
        external = group["signatureInterface"] == "external"
        if param is None or not external:
            skipped += len(group["tests"])
            continue
        pre = group["preHash"]
        for test in group["tests"]:
            pub = fips205.PublicKey(param, a2b_hex(test["pk"]))
            message = a2b_hex(test["message"])
            context = a2b_hex(test["context"]) if "context" in test else b""
            signature = a2b_hex(test["signature"])
            if pre == "preHash":
                digest = digest_message(test["hashAlg"], message)
                verif = pub.hash_verify(signature, digest, test["hashAlg"], context)
            elif pre == "pure":
                verif = pub.verify(signature, message, context)
            else:
                raise Exception(f"unexpected external preHash {pre}")
            loc = f"{group['parameterSet']} tgId={group['tgId']} tcId={test['tcId']}"
            if verif != test["testPassed"]:
                raise Exception(f"{loc} sigVer got {verif} wanted {test['testPassed']}")
            passed += 1
    print(f"Passed {passed} sigVer tests ({skipped} skipped)")


if __name__ == "__main__":
    run_keygen()
    run_siggen()
    run_sigver()
