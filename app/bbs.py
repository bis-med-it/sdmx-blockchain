"""BBS+ multi-message signatures with zero-knowledge selective disclosure.

Implements the construction of the paper's Section 8.4 (Definition "Selective-
disclosure VC"): a publisher signs the message vector

    m = (tx_hash, R, h_1, ..., h_n)

with a single BBS+ signature; a prover can then disclose any subset D of those
messages to a verifier and prove, in zero knowledge, that the disclosed values
were signed together with the (undisclosed) remainder --- without revealing the
hidden leaves. The on-chain Merkle root R is always among the disclosed messages,
so the verifier independently re-binds the disclosed leaves to R (condition (ii)
of the definition), giving integrity under the collision resistance of SHA3-512
regardless of the BBS+ key.

The scheme is the classic BBS+ signature (Au-Susilo-Mu / Camenisch-Drijvers-
Lehmann) over the pairing-friendly BLS12-381 curve, with a Fiat-Shamir
non-interactive proof of knowledge for selective disclosure. Message generators
are derived by hash-to-curve (independent, nothing-up-my-sleeve), so no discrete-
log relations are known between them.

This is a pure-Python implementation (via ``py_ecc``); it is intended as a
faithful, testable realization of the paper's protocol rather than a
performance-optimized production library.
"""
from __future__ import annotations

import hashlib
import secrets
from typing import Dict, List, Sequence, Tuple

from py_ecc.optimized_bls12_381 import (
    G1,
    G2,
    Z1,
    add,
    multiply,
    neg,
    normalize,
    pairing,
    curve_order,
    eq,
)
from py_ecc.bls.hash_to_curve import hash_to_G1

_ORDER = curve_order
_DST_GEN = b"SDMX-BBSPLUS-BLS12381-H2G1-GENERATORS-v1"
_DST_MSG = b"SDMX-BBSPLUS-MESSAGE-SCALAR-v1"


# --------------------------------------------------------------------------- #
# Scalar / point helpers
# --------------------------------------------------------------------------- #
def _rand_scalar() -> int:
    return 1 + secrets.randbelow(_ORDER - 1)


def _hash_to_scalar(data: bytes, dst: bytes = _DST_MSG) -> int:
    # Wide-reduction hash to Z_r (64 bytes -> mod order) for negligible bias.
    h = hashlib.sha512(dst + data).digest()
    return int.from_bytes(h, "big") % _ORDER


def message_to_scalar(message: str) -> int:
    """Map a message (e.g. a hex fingerprint or tx hash) to a scalar in Z_r."""
    return _hash_to_scalar(message.encode("utf-8"))


def _generator(index: int) -> "tuple":
    # Independent generator H_index via hash-to-curve (index 0 reserved for h0/s).
    return hash_to_G1(index.to_bytes(4, "big"), _DST_GEN, hashlib.sha256)


def _generators(count: int) -> List["tuple"]:
    # Returns [h0, h1, ..., h_count] : h0 blinds s, h1.. blind the messages.
    return [_generator(i) for i in range(count + 1)]


def _sum_points(points: Sequence["tuple"]) -> "tuple":
    acc = Z1
    for p in points:
        acc = add(acc, p)
    return acc


def _point_bytes(point: "tuple") -> bytes:
    if eq(point, Z1):
        return b"\x00" * 96
    x, y = normalize(point)
    return int(x).to_bytes(48, "big") + int(y).to_bytes(48, "big")


# --------------------------------------------------------------------------- #
# Key generation
# --------------------------------------------------------------------------- #
def keygen() -> Tuple[int, "tuple"]:
    """Return (secret_key x in Z_r, public_key w = g2^x in G2)."""
    x = _rand_scalar()
    w = multiply(G2, x)
    return x, w


def sk_to_hex(sk: int) -> str:
    return sk.to_bytes(32, "big").hex()


def sk_from_hex(h: str) -> int:
    return int.from_bytes(bytes.fromhex(h), "big")


def pk_to_hex(pk: "tuple") -> str:
    from py_ecc.optimized_bls12_381 import FQ2

    x, y = normalize(pk)
    xc = x.coeffs if isinstance(x, FQ2) else (int(x), 0)
    yc = y.coeffs if isinstance(y, FQ2) else (int(y), 0)
    parts = [int(xc[0]), int(xc[1]), int(yc[0]), int(yc[1])]
    return b"".join(int(p).to_bytes(48, "big") for p in parts).hex()


def pk_from_hex(h: str) -> "tuple":
    from py_ecc.optimized_bls12_381 import FQ2, FQ

    raw = bytes.fromhex(h)
    vals = [int.from_bytes(raw[i * 48:(i + 1) * 48], "big") for i in range(4)]
    x = FQ2([vals[0], vals[1]])
    y = FQ2([vals[2], vals[3]])
    return (x, y, FQ2.one())


# --------------------------------------------------------------------------- #
# Signing / verification
# --------------------------------------------------------------------------- #
def _commitment_B(messages_scalars: Sequence[int], s: int, gens: Sequence["tuple"]) -> "tuple":
    # B = g1 * h0^s * prod hi^{mi}
    terms = [G1, multiply(gens[0], s)]
    for i, m in enumerate(messages_scalars):
        terms.append(multiply(gens[i + 1], m % _ORDER))
    return _sum_points(terms)


def sign(sk: int, messages: Sequence[str]) -> Dict[str, str]:
    """Produce a BBS+ signature (A, e, s) over the ordered messages."""
    ms = [message_to_scalar(m) for m in messages]
    gens = _generators(len(ms))
    e = _rand_scalar()
    s = _rand_scalar()
    B = _commitment_B(ms, s, gens)
    exp = pow((e + sk) % _ORDER, -1, _ORDER)  # 1/(e+x)
    A = multiply(B, exp)
    return {"A": _point_bytes(A).hex(), "e": e.to_bytes(32, "big").hex(), "s": s.to_bytes(32, "big").hex()}


def _g1_from_hex(h: str) -> "tuple":
    from py_ecc.optimized_bls12_381 import FQ, is_on_curve, b

    raw = bytes.fromhex(h)
    x = int.from_bytes(raw[:48], "big")
    y = int.from_bytes(raw[48:96], "big")
    if x == 0 and y == 0:
        return Z1
    return (FQ(x), FQ(y), FQ(1))


def verify(pk: "tuple", signature: Dict[str, str], messages: Sequence[str]) -> bool:
    """Verify a BBS+ signature over all messages: e(A, w*g2^e) == e(B, g2)."""
    try:
        A = _g1_from_hex(signature["A"])
        e = int.from_bytes(bytes.fromhex(signature["e"]), "big")
        s = int.from_bytes(bytes.fromhex(signature["s"]), "big")
        ms = [message_to_scalar(m) for m in messages]
        gens = _generators(len(ms))
        B = _commitment_B(ms, s, gens)
        lhs = pairing(add(pk, multiply(G2, e)), A)
        rhs = pairing(G2, B)
        return lhs == rhs
    except Exception:
        return False


# --------------------------------------------------------------------------- #
# Selective-disclosure proof (Fiat-Shamir)
# --------------------------------------------------------------------------- #
def _challenge(points: Sequence["tuple"], disclosed: Dict[int, int], nonce: bytes) -> int:
    hasher = hashlib.sha512()
    for p in points:
        hasher.update(_point_bytes(p))
    for idx in sorted(disclosed):
        hasher.update(idx.to_bytes(4, "big"))
        hasher.update(disclosed[idx].to_bytes(32, "big"))
    hasher.update(nonce)
    return int.from_bytes(hasher.digest(), "big") % _ORDER


def prove(
    pk: "tuple",
    signature: Dict[str, str],
    messages: Sequence[str],
    disclosed_indices: Sequence[int],
    nonce: bytes,
) -> Dict:
    """Generate a selective-disclosure proof revealing only ``disclosed_indices``.

    Indices are 0-based positions into ``messages``. Returns a JSON-serializable
    proof dict plus the disclosed (index -> message) map.
    """
    A = _g1_from_hex(signature["A"])
    e = int.from_bytes(bytes.fromhex(signature["e"]), "big")
    s = int.from_bytes(bytes.fromhex(signature["s"]), "big")
    ms = [message_to_scalar(m) for m in messages]
    L = len(ms)
    gens = _generators(L)
    h0 = gens[0]
    B = _commitment_B(ms, s, gens)

    disclosed = set(disclosed_indices)
    hidden = [i for i in range(L) if i not in disclosed]

    r1 = _rand_scalar()
    r2 = _rand_scalar()
    r3 = pow(r1, -1, _ORDER)

    A_prime = multiply(A, r1)
    # Abar = A'^{-e} * B^{r1}
    Abar = add(multiply(A_prime, (-e) % _ORDER), multiply(B, r1))
    # d = B^{r1} * h0^{-r2}
    d = add(multiply(B, r1), multiply(h0, (-r2) % _ORDER))
    s_prime = (s - r2 * r3) % _ORDER

    # T1 = Abar - d ; relation: T1 = A'^{-e} * h0^{r2}
    # T2 = -g1 - sum_{i in D} hi^{mi} ; relation: T2 = d^{-r3} * h0^{s'} * prod_{i in U} hi^{mi}
    # (equations in additive notation over G1)
    # Blindings
    e_b = _rand_scalar()
    r2_b = _rand_scalar()
    r3_b = _rand_scalar()
    s_b = _rand_scalar()
    m_b = {i: _rand_scalar() for i in hidden}

    C1 = add(multiply(A_prime, (-e_b) % _ORDER), multiply(h0, r2_b))
    c2_terms = [multiply(d, (-r3_b) % _ORDER), multiply(h0, s_b)]
    for i in hidden:
        c2_terms.append(multiply(gens[i + 1], m_b[i]))
    C2 = _sum_points(c2_terms)

    disclosed_scalars = {i: ms[i] for i in disclosed}
    c = _challenge([A_prime, Abar, d, C1, C2], disclosed_scalars, nonce)

    e_hat = (e_b + c * e) % _ORDER
    r2_hat = (r2_b + c * r2) % _ORDER
    r3_hat = (r3_b + c * r3) % _ORDER
    s_hat = (s_b + c * s_prime) % _ORDER
    m_hat = {i: (m_b[i] + c * ms[i]) % _ORDER for i in hidden}

    return {
        "L": L,
        "disclosed": {i: messages[i] for i in sorted(disclosed)},
        "A_prime": _point_bytes(A_prime).hex(),
        "Abar": _point_bytes(Abar).hex(),
        "d": _point_bytes(d).hex(),
        "c": c.to_bytes(32, "big").hex(),
        "e_hat": e_hat.to_bytes(32, "big").hex(),
        "r2_hat": r2_hat.to_bytes(32, "big").hex(),
        "r3_hat": r3_hat.to_bytes(32, "big").hex(),
        "s_hat": s_hat.to_bytes(32, "big").hex(),
        "m_hat": {str(i): m_hat[i].to_bytes(32, "big").hex() for i in hidden},
    }


def proof_verify(pk: "tuple", proof: Dict, disclosed_messages: Dict[int, str], nonce: bytes) -> bool:
    """Verify a selective-disclosure proof against the disclosed messages."""
    try:
        L = int(proof["L"])
        gens = _generators(L)
        h0 = gens[0]
        A_prime = _g1_from_hex(proof["A_prime"])
        Abar = _g1_from_hex(proof["Abar"])
        d = _g1_from_hex(proof["d"])
        c = int.from_bytes(bytes.fromhex(proof["c"]), "big")
        e_hat = int.from_bytes(bytes.fromhex(proof["e_hat"]), "big")
        r2_hat = int.from_bytes(bytes.fromhex(proof["r2_hat"]), "big")
        r3_hat = int.from_bytes(bytes.fromhex(proof["r3_hat"]), "big")
        s_hat = int.from_bytes(bytes.fromhex(proof["s_hat"]), "big")
        m_hat = {int(k): int.from_bytes(bytes.fromhex(v), "big") for k, v in proof["m_hat"].items()}

        # A' must not be identity, and pairing relation binds A'/Abar to the key.
        if eq(A_prime, Z1):
            return False
        if pairing(pk, A_prime) != pairing(G2, Abar):
            return False

        disclosed = {i: message_to_scalar(m) for i, m in disclosed_messages.items()}
        hidden = [i for i in range(L) if i not in disclosed]
        if set(m_hat.keys()) != set(hidden):
            return False

        # T1 = Abar - d
        T1 = add(Abar, neg(d))
        # C1' = A'^{-e_hat} * h0^{r2_hat} * T1^{-c}
        C1p = _sum_points([
            multiply(A_prime, (-e_hat) % _ORDER),
            multiply(h0, r2_hat),
            multiply(T1, (-c) % _ORDER),
        ])

        # T2 = -g1 - sum_{i in D} hi^{mi}
        t2_terms = [neg(G1)]
        for i, m in disclosed.items():
            t2_terms.append(multiply(gens[i + 1], (-m) % _ORDER))
        T2 = _sum_points(t2_terms)
        # C2' = d^{-r3_hat} * h0^{s_hat} * prod_{i in U} hi^{m_hat_i} * T2^{-c}
        c2_terms = [multiply(d, (-r3_hat) % _ORDER), multiply(h0, s_hat)]
        for i in hidden:
            c2_terms.append(multiply(gens[i + 1], m_hat[i]))
        c2_terms.append(multiply(T2, (-c) % _ORDER))
        C2p = _sum_points(c2_terms)

        c_prime = _challenge([A_prime, Abar, d, C1p, C2p], disclosed, nonce)
        return c_prime == c
    except Exception:
        return False
