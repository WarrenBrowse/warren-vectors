#!/usr/bin/env python3
"""Generates `device_revocation_v1.json` (warren-core doc 115, signed
revocation, audit finding X-01): the statement a wallet holder signs when it
revokes one of its devices, which the API stores and returns in the 403
`device_revoked` body, and which the revoked device verifies with its own
wallet key and device id before it erases anything.

The signature is made with the `cryptography` package (OpenSSL); the validator
recomputes every signature with the standard-library Ed25519 of
`ed25519_ref.py`: two implementations, none of them Warren's. Re-running this
script reproduces the committed file byte for byte; the vector is frozen, so
it is a provenance record and never a way to change it.

Needs `pip install cryptography`.
"""

import base64
import json
import pathlib

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

ROOT = pathlib.Path(__file__).resolve().parent.parent

DOMAIN = b"warren/device-revocation/v1"

WALLET_SEED = bytes([0x5A]) * 32
OTHER_WALLET_SEED = bytes([0x5B]) * 32
# The revoked device, and a sibling of the same account: the two device ids of
# device_registry_v1.json.
DEVICE = bytes(range(16))
OTHER_DEVICE = bytes([0xFF]) * 16
REVOKED_AT = 1_794_960_000


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def signer(seed: bytes):
    key = Ed25519PrivateKey.from_private_bytes(seed)
    return key, key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def message(wallet_pk: bytes, device_id: bytes, revoked_at: int) -> bytes:
    return DOMAIN + wallet_pk + device_id + revoked_at.to_bytes(8, "big")


def statement(revoked_at: int, signature_hex: str) -> dict:
    return {"revoked_at_unix_secs": revoked_at, "signature_hex": signature_hex}


def refusal(revocation) -> dict:
    out = {"error": "device_revoked"}
    if revocation is not None:
        out["revocation"] = revocation
    return out


def compact(obj) -> str:
    return json.dumps(obj, separators=(",", ":"))


def device_revocation():
    key, wallet_pk = signer(WALLET_SEED)
    other_key, other_pk = signer(OTHER_WALLET_SEED)
    msg = message(wallet_pk, DEVICE, REVOKED_AT)
    sig = key.sign(msg)
    signed = statement(REVOKED_AT, sig.hex())

    sibling_sig = key.sign(message(wallet_pk, OTHER_DEVICE, REVOKED_AT))
    foreign_sig = other_key.sign(message(other_pk, DEVICE, REVOKED_AT))
    flipped = bytearray(sig)
    flipped[0] ^= 0x01

    def case(name, comment, body, expect):
        return {"name": name, "_comment": comment, "refusal_json": compact(body), "expect": expect}

    return {
        "version": 1,
        "_comment": (
            "Signed device revocation v1 (warren-core doc 115, audit finding X-01). A wallet holder "
            "revoking one of its devices signs, with the wallet's Ed25519 key (the X-Warren signing "
            "key), message = 'warren/device-revocation/v1' (27 bytes) || wallet public key (32 bytes) "
            "|| device id (16 bytes) || revoked_at (u64 BE, unix seconds), 83 bytes, and sends "
            "{revoked_at_unix_secs, signature_hex} as the body of the wallet-signed DELETE "
            "/v1/devices/{device_id}. The API checks it against the signing wallet and the path's "
            "device id, stores it, and returns it as the revocation member of every 403 "
            "device_revoked body for that device. The revoked device verifies it with its own wallet "
            "public key and its own device id: ok means it may erase its identity; any other outcome "
            "(unsigned, malformed, bad_signature) means it disconnects and keeps its identity, "
            "because nothing proves the wallet holder asked. The refusal stays readable by an older "
            "client, which compares the error string and ignores the unknown member. Synthetic "
            "inputs only."
        ),
        "domain_utf8": DOMAIN.decode(),
        "message_len": len(msg),
        "wallet": {"signing_seed_hex": WALLET_SEED.hex(), "pubkey_hex": wallet_pk.hex()},
        "device_id": {"b64url": b64url(DEVICE), "bytes_hex": DEVICE.hex()},
        "revoked_at_unix_secs": REVOKED_AT,
        "message_hex": msg.hex(),
        "signature_hex": sig.hex(),
        "revocation_request_json": compact(signed),
        "refusal_json": compact(refusal(signed)),
        "invalid": [
            case(
                "unsigned",
                "The bare refusal every server answered before this vector, and what a server "
                "answers for a device revoked by a client that sent no statement.",
                refusal(None),
                "unsigned",
            ),
            case(
                "sibling_device",
                "A genuine statement of the same wallet for another of its devices: the API "
                "serving one device's revocation to another.",
                refusal(statement(REVOKED_AT, sibling_sig.hex())),
                "bad_signature",
            ),
            case(
                "foreign_wallet",
                "A statement for this device id signed by another wallet: whoever forges the "
                "answer without the wallet key.",
                refusal(statement(REVOKED_AT, foreign_sig.hex())),
                "bad_signature",
            ),
            case(
                "shifted_date",
                "The genuine signature under another revocation date.",
                refusal(statement(REVOKED_AT + 1, sig.hex())),
                "bad_signature",
            ),
            case(
                "flipped_bit",
                "The genuine statement with one signature bit flipped.",
                refusal(statement(REVOKED_AT, bytes(flipped).hex())),
                "bad_signature",
            ),
            case(
                "truncated_signature",
                "A 63-byte signature.",
                refusal(statement(REVOKED_AT, sig[:63].hex())),
                "malformed",
            ),
            case(
                "not_hex",
                "A signature that is not hex.",
                refusal(statement(REVOKED_AT, "zz" * 64)),
                "malformed",
            ),
        ],
    }


def main():
    out = ROOT / "device_revocation_v1.json"
    out.write_text(json.dumps(device_revocation(), indent=2) + "\n")
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
