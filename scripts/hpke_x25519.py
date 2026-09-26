"""Standard-library HPKE (RFC 9180) for one suite, used to generate and check
the route admission vectors independently of every Warren implementation.

Suite: base mode, DHKEM(X25519, HKDF-SHA256) 0x0020, HKDF-SHA256 0x0001,
ChaCha20Poly1305 0x0003. X25519 follows RFC 7748, ChaCha20-Poly1305 follows
RFC 8439. Nothing here is constant time: it is a reference for test vectors,
never a production implementation.
"""

import hashlib
import hmac

_P = 2**255 - 19
_A24 = 121665
_BASE_U = (9).to_bytes(32, "little")


def x25519(scalar: bytes, u: bytes) -> bytes:
    k = bytearray(scalar)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    k_int = int.from_bytes(k, "little")
    ub = bytearray(u)
    ub[31] &= 127
    x1 = int.from_bytes(ub, "little") % _P
    x2, z2, x3, z3 = 1, 0, x1, 1
    swap = 0
    for t in reversed(range(255)):
        bit = (k_int >> t) & 1
        swap ^= bit
        if swap:
            x2, x3 = x3, x2
            z2, z3 = z3, z2
        swap = bit
        a = (x2 + z2) % _P
        aa = a * a % _P
        b = (x2 - z2) % _P
        bb = b * b % _P
        e = (aa - bb) % _P
        c = (x3 + z3) % _P
        d = (x3 - z3) % _P
        da = d * a % _P
        cb = c * b % _P
        x3 = (da + cb) ** 2 % _P
        z3 = x1 * (da - cb) ** 2 % _P
        x2 = aa * bb % _P
        z2 = e * (aa + _A24 * e) % _P
    if swap:
        x2, x3 = x3, x2
        z2, z3 = z3, z2
    return (x2 * pow(z2, _P - 2, _P) % _P).to_bytes(32, "little")


def x25519_public(scalar: bytes) -> bytes:
    return x25519(scalar, _BASE_U)


def _rotl(v: int, c: int) -> int:
    return ((v << c) & 0xFFFFFFFF) | (v >> (32 - c))


def _chacha20_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    def quarter(s, a, b, c, d):
        s[a] = (s[a] + s[b]) & 0xFFFFFFFF
        s[d] = _rotl(s[d] ^ s[a], 16)
        s[c] = (s[c] + s[d]) & 0xFFFFFFFF
        s[b] = _rotl(s[b] ^ s[c], 12)
        s[a] = (s[a] + s[b]) & 0xFFFFFFFF
        s[d] = _rotl(s[d] ^ s[a], 8)
        s[c] = (s[c] + s[d]) & 0xFFFFFFFF
        s[b] = _rotl(s[b] ^ s[c], 7)

    words = lambda raw: [int.from_bytes(raw[i : i + 4], "little") for i in range(0, len(raw), 4)]
    state = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574] + words(key) + [counter] + words(nonce)
    work = list(state)
    for _ in range(10):
        quarter(work, 0, 4, 8, 12)
        quarter(work, 1, 5, 9, 13)
        quarter(work, 2, 6, 10, 14)
        quarter(work, 3, 7, 11, 15)
        quarter(work, 0, 5, 10, 15)
        quarter(work, 1, 6, 11, 12)
        quarter(work, 2, 7, 8, 13)
        quarter(work, 3, 4, 9, 14)
    return b"".join(((w + s) & 0xFFFFFFFF).to_bytes(4, "little") for w, s in zip(work, state))


def _chacha20_xor(key: bytes, counter: int, nonce: bytes, data: bytes) -> bytes:
    out = bytearray()
    for block in range(0, len(data), 64):
        stream = _chacha20_block(key, counter + block // 64, nonce)
        chunk = data[block : block + 64]
        out += bytes(a ^ b for a, b in zip(chunk, stream))
    return bytes(out)


def _poly1305(key: bytes, msg: bytes) -> bytes:
    r = int.from_bytes(key[:16], "little") & 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
    s = int.from_bytes(key[16:32], "little")
    p = 2**130 - 5
    acc = 0
    for i in range(0, len(msg), 16):
        chunk = msg[i : i + 16]
        acc = (acc + int.from_bytes(chunk + b"\x01", "little")) * r % p
    return ((acc + s) % 2**128).to_bytes(16, "little")


def _pad16(data: bytes) -> bytes:
    return b"\x00" * (-len(data) % 16)


def _mac_data(aad: bytes, ct: bytes) -> bytes:
    return aad + _pad16(aad) + ct + _pad16(ct) + len(aad).to_bytes(8, "little") + len(ct).to_bytes(8, "little")


def chacha20poly1305_seal(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
    otk = _chacha20_block(key, 0, nonce)[:32]
    ct = _chacha20_xor(key, 1, nonce, plaintext)
    return ct + _poly1305(otk, _mac_data(aad, ct))


def chacha20poly1305_open(key: bytes, nonce: bytes, sealed: bytes, aad: bytes):
    """The plaintext, or None when the tag does not verify."""
    if len(sealed) < 16:
        return None
    ct, tag = sealed[:-16], sealed[-16:]
    otk = _chacha20_block(key, 0, nonce)[:32]
    if not hmac.compare_digest(_poly1305(otk, _mac_data(aad, ct)), tag):
        return None
    return _chacha20_xor(key, 1, nonce, ct)


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    out, block, counter = b"", b"", 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        out += block
        counter += 1
    return out[:length]


KEM_ID = 0x0020
KDF_ID = 0x0001
AEAD_ID = 0x0003
_SUITE_KEM = b"KEM" + KEM_ID.to_bytes(2, "big")
_SUITE_HPKE = b"HPKE" + KEM_ID.to_bytes(2, "big") + KDF_ID.to_bytes(2, "big") + AEAD_ID.to_bytes(2, "big")


def _labeled_extract(salt: bytes, label: bytes, ikm: bytes, suite: bytes) -> bytes:
    return hkdf_extract(salt, b"HPKE-v1" + suite + label + ikm)


def _labeled_expand(prk: bytes, label: bytes, info: bytes, length: int, suite: bytes) -> bytes:
    labeled = length.to_bytes(2, "big") + b"HPKE-v1" + suite + label + info
    return hkdf_expand(prk, labeled, length)


def derive_key_pair(ikm: bytes):
    """RFC 9180 DeriveKeyPair for DHKEM(X25519, HKDF-SHA256): (sk, pk)."""
    dkp_prk = _labeled_extract(b"", b"dkp_prk", ikm, _SUITE_KEM)
    sk = _labeled_expand(dkp_prk, b"sk", b"", 32, _SUITE_KEM)
    return sk, x25519_public(sk)


def _shared_secret(dh: bytes, kem_context: bytes) -> bytes:
    eae_prk = _labeled_extract(b"", b"eae_prk", dh, _SUITE_KEM)
    return _labeled_expand(eae_prk, b"shared_secret", kem_context, 32, _SUITE_KEM)


def _key_schedule_base(shared_secret: bytes, info: bytes):
    psk_id_hash = _labeled_extract(b"", b"psk_id_hash", b"", _SUITE_HPKE)
    info_hash = _labeled_extract(b"", b"info_hash", info, _SUITE_HPKE)
    context = b"\x00" + psk_id_hash + info_hash
    secret = _labeled_extract(shared_secret, b"secret", b"", _SUITE_HPKE)
    key = _labeled_expand(secret, b"key", context, 32, _SUITE_HPKE)
    base_nonce = _labeled_expand(secret, b"base_nonce", context, 12, _SUITE_HPKE)
    return key, base_nonce


def seal_base(pk_r: bytes, info: bytes, aad: bytes, plaintext: bytes, eph_ikm: bytes):
    """Single-shot base-mode seal with the ephemeral key derived from
    `eph_ikm`: (enc, ciphertext_with_tag)."""
    sk_e, pk_e = derive_key_pair(eph_ikm)
    dh = x25519(sk_e, pk_r)
    if dh == b"\x00" * 32:
        raise ValueError("small-order recipient key")
    shared = _shared_secret(dh, pk_e + pk_r)
    key, nonce = _key_schedule_base(shared, info)
    return pk_e, chacha20poly1305_seal(key, nonce, plaintext, aad)


def open_base(sk_r: bytes, enc: bytes, info: bytes, aad: bytes, ciphertext: bytes):
    """Single-shot base-mode open: the plaintext, or None on failure."""
    dh = x25519(sk_r, enc)
    if dh == b"\x00" * 32:
        return None
    shared = _shared_secret(dh, enc + x25519_public(sk_r))
    key, nonce = _key_schedule_base(shared, info)
    return chacha20poly1305_open(key, nonce, ciphertext, aad)
