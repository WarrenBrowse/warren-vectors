#!/usr/bin/env python3
"""Generates `route_kem_signature_v1.json` (warren-core doc 107 section 6.5):
the API's Ed25519 signature over its route KEM key, as served in the
`route_admission` block of the session token directory.

The signature is made with the `cryptography` package (OpenSSL), the KEM key
is derived with the standard-library HPKE of `hpke_x25519.py`, and the
validator recomputes every signature with the standard-library Ed25519 of
`ed25519_ref.py`: three implementations, none of them Warren's. Re-running
this script reproduces the committed file byte for byte; the vector is frozen,
so it is a provenance record and never a way to change it.

Needs `pip install cryptography`.
"""

import json
import pathlib

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

import hpke_x25519 as hpke

ROOT = pathlib.Path(__file__).resolve().parent.parent

DOMAIN = b"warren/route-kem-sig/v1"
KEM_INFO = b"warren/route-kem/v1"

# The same synthetic API signing seed as route_admission_v1.json: the API
# derives its route KEM key from the key it signs with.
SIGNING_SEED = bytes([0x71]) * 32
OTHER_SEED = bytes([0x72]) * 32
BLOCK_VERSION = 1
KEY_ID = 1
# A UTC day boundary, as the API rounds its validity to whole days.
VALID_UNTIL = 1_790_035_200
VERIFY_AT = VALID_UNTIL - 86_400
MAX_ROUTES = 32
EXIT_IDS = [bytes([0xA2]) * 16]


def kem_public_key(seed: bytes, key_id: int) -> bytes:
    ikm = hpke.hkdf_expand(hpke.hkdf_extract(b"", seed), KEM_INFO + bytes([key_id]), 32)
    return hpke.derive_key_pair(ikm)[1]


def signer(seed: bytes):
    key = Ed25519PrivateKey.from_private_bytes(seed)
    public = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return key, public


def message(version: int, key_id: int, kem_pk: bytes, valid_until: int) -> bytes:
    return (
        DOMAIN
        + version.to_bytes(4, "big")
        + bytes([key_id])
        + kem_pk
        + valid_until.to_bytes(8, "big")
    )


def block(version, key_id, kem_pk, signature, valid_until):
    out = {
        "version": version,
        "kem_key_id": key_id,
        "kem_pubkey_hex": kem_pk.hex(),
        "max_routes_per_anchor": MAX_ROUTES,
        "exit_ids_hex": [e.hex() for e in EXIT_IDS],
    }
    if signature is not None:
        out["kem_signature"] = {"valid_until": valid_until, "signature_hex": signature.hex()}
    return out


def route_kem_signature():
    key, server_pk = signer(SIGNING_SEED)
    other_key, other_pk = signer(OTHER_SEED)
    kem_pk = kem_public_key(SIGNING_SEED, KEY_ID)
    other_kem_pk = kem_public_key(OTHER_SEED, KEY_ID)
    msg = message(BLOCK_VERSION, KEY_ID, kem_pk, VALID_UNTIL)
    sig = key.sign(msg)
    other_msg = message(BLOCK_VERSION, KEY_ID, other_kem_pk, VALID_UNTIL)
    other_sig = other_key.sign(other_msg)
    served = block(BLOCK_VERSION, KEY_ID, kem_pk, sig, VALID_UNTIL)

    def case(name, comment, blk, expect, now=VERIFY_AT):
        return {"name": name, "_comment": comment, "now": now, "block": blk, "expect": expect}

    return {
        "version": 1,
        "_comment": (
            "Route KEM key signature v1 (warren-core doc 107 section 6.5). The API signs the route KEM "
            "key it serves in the route_admission block of GET /v1/tokens/keys with its Ed25519 server "
            "key, the key whose public half every client already pins for the signed relay list and the "
            "multi-hop directory envelope. message = 'warren/route-kem-sig/v1' (23 bytes) || block "
            "version (u32 BE) || kem_key_id (u8) || kem_pubkey (32 bytes, X25519) || valid_until (u64 BE, "
            "unix seconds), 68 bytes. A client uses the key only when the signature verifies under a "
            "pinned server key and now < valid_until; max_routes_per_anchor and exit_ids_hex are not "
            "covered, since a forged value there can only cost the client route admission. The signing "
            "seed is the one route_admission_v1.json derives its KEM key from. Every invalid case must "
            "be refused with its expect outcome. Synthetic inputs only."
        ),
        "domain_utf8": DOMAIN.decode(),
        "message_len": len(msg),
        "signer": {
            "signing_seed_hex": SIGNING_SEED.hex(),
            "server_pubkey_hex": server_pk.hex(),
        },
        "kem_key": {"signing_seed_hex": SIGNING_SEED.hex(), "key_id": KEY_ID, "pk_hex": kem_pk.hex()},
        "valid_until": VALID_UNTIL,
        "verify_at": VERIFY_AT,
        "message_hex": msg.hex(),
        "signature_hex": sig.hex(),
        "route_admission_json": json.dumps(served, separators=(",", ":")),
        "invalid": [
            case(
                "substituted_kem_key",
                "Another KEM key under the served signature: what a TLS interceptor would serve.",
                block(BLOCK_VERSION, KEY_ID, other_kem_pk, sig, VALID_UNTIL),
                "bad_signature",
            ),
            case(
                "substituted_kem_key_signed_by_another_key",
                "Another KEM key signed by a key no client pins.",
                block(BLOCK_VERSION, KEY_ID, other_kem_pk, other_sig, VALID_UNTIL),
                "bad_signature",
            ),
            case(
                "other_key_id",
                "The key id is signed: a blob sealed under it would be opened with another key.",
                block(BLOCK_VERSION, KEY_ID + 1, kem_pk, sig, VALID_UNTIL),
                "bad_signature",
            ),
            case(
                "extended_validity",
                "The validity is signed: an old signature cannot be stretched.",
                block(BLOCK_VERSION, KEY_ID, kem_pk, sig, VALID_UNTIL + 86_400),
                "bad_signature",
            ),
            case(
                "other_block_version",
                "The block version is signed.",
                block(BLOCK_VERSION + 1, KEY_ID, kem_pk, sig, VALID_UNTIL),
                "bad_signature",
            ),
            case(
                "expired",
                "valid_until is exclusive: at that second the signature no longer vouches for the key.",
                served,
                "expired",
                now=VALID_UNTIL,
            ),
            case(
                "unsigned",
                "A block with no signature is never trusted: route admission is unavailable.",
                block(BLOCK_VERSION, KEY_ID, kem_pk, None, VALID_UNTIL),
                "unsigned",
            ),
            case(
                "truncated_signature",
                "A signature that is not 64 bytes is malformed.",
                block(BLOCK_VERSION, KEY_ID, kem_pk, sig[:63], VALID_UNTIL),
                "malformed",
            ),
        ],
    }


def main() -> None:
    path = ROOT / "route_kem_signature_v1.json"
    path.write_text(json.dumps(route_kem_signature(), indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
