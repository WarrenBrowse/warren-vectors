#!/usr/bin/env python3
"""Generates `route_admission_v1.json` and the route admission entries of
`control.json` (warren-core doc 107 sections 6 and 7) from fixed synthetic
inputs, with the standard-library HPKE of `hpke_x25519.py`, independently of
every Warren implementation. Re-running it reproduces the committed files
byte for byte; the vectors are frozen, so it is a provenance record and never
a way to change them.
"""

import hashlib
import json
import pathlib

import hpke_x25519 as hpke

ROOT = pathlib.Path(__file__).resolve().parent.parent

KEM_INFO = b"warren/route-kem/v1"
ANCHOR_INFO = b"warren/route-anchor/v1"
LOCATOR_INFO = b"warren/route-locator/v1"
ANCHOR_REF_DOMAIN = b"warren/route-anchor-ref/v1"
ROUTE_SERIAL_DOMAIN = b"warren/route-serial/v1"

SIGNING_SEED = bytes([0x71]) * 32
KEY_ID = 1
ANCHOR_SECRET = bytes([0x3C]) * 32
SERIAL = bytes([0x5E]) * 32
EXIT_ID = bytes([0xA2]) * 16
ANCHOR_EPH_IKM = bytes([0x11]) * 32
LOCATOR_EPH_IKM = bytes([0x22]) * 32
OTHER_SERIAL = bytes([0x5F]) * 32
OTHER_EXIT_ID = bytes([0xA3]) * 16
SESSION_TOKEN = bytes([0xCD]) * 354


def kem_key():
    ikm = hpke.hkdf_expand(hpke.hkdf_extract(b"", SIGNING_SEED), KEM_INFO + bytes([KEY_ID]), 32)
    sk, pk = hpke.derive_key_pair(ikm)
    return ikm, sk, pk


def seal(pk: bytes, info: bytes, aad: bytes, eph_ikm: bytes):
    enc, ct = hpke.seal_base(pk, info, aad, ANCHOR_SECRET, eph_ikm)
    assert len(enc) == 32 and len(ct) == 48
    return enc, ct, bytes([KEY_ID]) + enc + ct


def route_admission():
    ikm, sk, pk = kem_key()
    anchor_aad = ANCHOR_INFO + SERIAL
    locator_aad = LOCATOR_INFO + EXIT_ID
    a_enc, a_ct, anchor = seal(pk, ANCHOR_INFO, anchor_aad, ANCHOR_EPH_IKM)
    l_enc, l_ct, locator = seal(pk, LOCATOR_INFO, locator_aad, LOCATOR_EPH_IKM)
    anchor_ref = hashlib.sha256(ANCHOR_REF_DOMAIN + ANCHOR_SECRET).digest()
    route_serial = hashlib.sha256(ROUTE_SERIAL_DOMAIN + anchor_ref + EXIT_ID).digest()
    flipped = bytearray(locator)
    flipped[-1] ^= 0x01
    rekeyed = bytearray(anchor)
    rekeyed[0] = KEY_ID + 1
    return {
        "version": 1,
        "_comment": (
            "Route admission by anchor v1 (warren-core doc 107 section 6). HPKE RFC 9180 base mode, "
            "single shot, DHKEM(X25519, HKDF-SHA256) 0x0020, HKDF-SHA256 0x0001, ChaCha20Poly1305 0x0003. "
            "The API route KEM key pair is DeriveKeyPair(HKDF-SHA256(salt empty, ikm = API signing key "
            "secret bytes, info = 'warren/route-kem/v1' || key_id, 32 bytes)). A sealed blob "
            "(SealedToApi) is key_id (1 byte) || enc (32) || ciphertext of the 32-byte anchor secret with "
            "its 16-byte tag (48), 81 bytes with no length prefix. The anchor registration seals with "
            "info 'warren/route-anchor/v1' and associated data that info || the 32-byte token serial the "
            "main session was admitted on; the route locator with info 'warren/route-locator/v1' and "
            "associated data that info || the 16-byte exit id of the route exit. Each seal here draws its "
            "ephemeral key from DeriveKeyPair(eph_ikm) instead of randomness, so the bytes are "
            "reproducible. anchor_ref = SHA-256('warren/route-anchor-ref/v1' || secret) and route_serial "
            "= SHA-256('warren/route-serial/v1' || anchor_ref || exit_id). Every invalid_opens case must "
            "be refused by the opener. Synthetic inputs only."
        ),
        "suite": {"mode": 0, "kem_id": hpke.KEM_ID, "kdf_id": hpke.KDF_ID, "aead_id": hpke.AEAD_ID},
        "sealed_len": 81,
        "kem_key": {
            "signing_seed_hex": SIGNING_SEED.hex(),
            "key_id": KEY_ID,
            "hkdf_salt_hex": "",
            "hkdf_info_hex": (KEM_INFO + bytes([KEY_ID])).hex(),
            "ikm_hex": ikm.hex(),
            "sk_hex": sk.hex(),
            "pk_hex": pk.hex(),
        },
        "anchor_secret_hex": ANCHOR_SECRET.hex(),
        "anchor_seal": {
            "serial_hex": SERIAL.hex(),
            "info_utf8": ANCHOR_INFO.decode(),
            "aad_hex": anchor_aad.hex(),
            "eph_ikm_hex": ANCHOR_EPH_IKM.hex(),
            "enc_hex": a_enc.hex(),
            "ct_hex": a_ct.hex(),
            "sealed_hex": anchor.hex(),
        },
        "locator_seal": {
            "exit_id_hex": EXIT_ID.hex(),
            "info_utf8": LOCATOR_INFO.decode(),
            "aad_hex": locator_aad.hex(),
            "eph_ikm_hex": LOCATOR_EPH_IKM.hex(),
            "enc_hex": l_enc.hex(),
            "ct_hex": l_ct.hex(),
            "sealed_hex": locator.hex(),
        },
        "derived": {
            "anchor_ref_domain_utf8": ANCHOR_REF_DOMAIN.decode(),
            "anchor_ref_hex": anchor_ref.hex(),
            "route_serial_domain_utf8": ROUTE_SERIAL_DOMAIN.decode(),
            "exit_id_hex": EXIT_ID.hex(),
            "route_serial_hex": route_serial.hex(),
        },
        "invalid_opens": [
            {
                "name": "anchor_opened_with_another_serial",
                "_comment": "The anchor blob is bound to the serial of the main session that sent it.",
                "sealed_hex": anchor.hex(),
                "open_as": "anchor",
                "serial_hex": OTHER_SERIAL.hex(),
            },
            {
                "name": "locator_opened_by_another_exit",
                "_comment": "A locator sealed for one exit opens only when that exit presents it.",
                "sealed_hex": locator.hex(),
                "open_as": "locator",
                "exit_id_hex": OTHER_EXIT_ID.hex(),
            },
            {
                "name": "anchor_blob_presented_as_locator",
                "_comment": "The info strings separate the two uses: an anchor blob is never a locator.",
                "sealed_hex": anchor.hex(),
                "open_as": "locator",
                "exit_id_hex": EXIT_ID.hex(),
            },
            {
                "name": "unknown_key_id",
                "_comment": "A blob naming a key id the opener does not hold is refused before any HPKE work.",
                "sealed_hex": bytes(rekeyed).hex(),
                "open_as": "anchor",
                "serial_hex": SERIAL.hex(),
            },
            {
                "name": "locator_with_a_flipped_tag_byte",
                "_comment": "Any altered byte fails the AEAD tag.",
                "sealed_hex": bytes(flipped).hex(),
                "open_as": "locator",
                "exit_id_hex": EXIT_ID.hex(),
            },
        ],
    }


def varint(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def option(value: bytes | None) -> bytes:
    return b"\x00" if value is None else b"\x01" + value


def control(discriminant: int, payload: bytes) -> str:
    return (bytes([0xC0, 0x03, discriminant]) + payload).hex()


def control_entries(anchor: bytes, locator: bytes):
    def ip_request_route(prefer, wants_ipv6, wants_daita):
        return control(
            7,
            option(bytes(prefer) if prefer else None)
            + bytes([wants_ipv6])
            + locator
            + bytes([wants_daita]),
        )

    earlier = "Discriminants 0 to 6 keep their bytes: the variant is appended."
    return [
        {
            "name": "ip_request_route_minimal",
            "_comment": "IpRequestRoute (doc 107 section 7.1): variant tag 7, prefer_ipv4 None, wants_ipv6 false, "
            "the 81-byte route locator raw (the locator_seal of route_admission_v1.json), wants_daita false. "
            "No token, no wallet key, no proof of possession. " + earlier,
            "discriminant": 7,
            "wants_ipv6": False,
            "route_locator_hex": locator.hex(),
            "wants_daita": False,
            "bytes_hex": ip_request_route(None, False, False),
        },
        {
            "name": "ip_request_route_full",
            "_comment": "IpRequestRoute with prefer_ipv4 Some(10.66.0.42), wants_ipv6 true, wants_daita true. " + earlier,
            "discriminant": 7,
            "prefer_ipv4": [10, 66, 0, 42],
            "wants_ipv6": True,
            "route_locator_hex": locator.hex(),
            "wants_daita": True,
            "bytes_hex": ip_request_route([10, 66, 0, 42], True, True),
        },
        {
            "name": "route_rejected_anchor_unknown",
            "_comment": "RouteRejected (section 7.2): variant tag 8, reason_code 1 = anchor unknown. "
            "Codes: 0 unspecified, 1 anchor unknown, 2 route limit, 3 not offered, 4 unavailable. " + earlier,
            "discriminant": 8,
            "reason_code": 1,
            "bytes_hex": control(8, bytes([1])),
        },
        {
            "name": "route_rejected_route_limit",
            "_comment": "RouteRejected with reason_code 2 = route limit. " + earlier,
            "discriminant": 8,
            "reason_code": 2,
            "bytes_hex": control(8, bytes([2])),
        },
        {
            "name": "route_anchor_request",
            "_comment": "RouteAnchorRequest (section 7.3): variant tag 9, the 81-byte sealed anchor raw (the "
            "anchor_seal of route_admission_v1.json), session_token None. 85 bytes. " + earlier,
            "discriminant": 9,
            "sealed_anchor_hex": anchor.hex(),
            "bytes_hex": control(9, anchor + option(None)),
        },
        {
            "name": "route_anchor_request_with_token",
            "_comment": "RouteAnchorRequest carrying a session token after a needs_token ack: Some, then the "
            "354 raw token bytes with no length prefix, as in IpRequestV7. 439 bytes. " + earlier,
            "discriminant": 9,
            "sealed_anchor_hex": anchor.hex(),
            "session_token_hex": SESSION_TOKEN.hex(),
            "bytes_hex": control(9, anchor + option(SESSION_TOKEN)),
        },
        {
            "name": "route_anchor_ack_bound",
            "_comment": "RouteAnchorAck (section 7.4): variant tag 10, status 0 = bound, max_routes 256 as a "
            "postcard varint (two bytes, 0x80 0x02). Status: 0 bound, 1 needs token, 2 not eligible, "
            "3 refused, 4 unavailable, 5 lost. " + earlier,
            "discriminant": 10,
            "status": 0,
            "max_routes": 256,
            "bytes_hex": control(10, bytes([0]) + varint(256)),
        },
        {
            "name": "route_anchor_ack_lost",
            "_comment": "RouteAnchorAck with status 5 = lost (the exit's renewal found no anchor; the client "
            "resends its request) and max_routes 0. " + earlier,
            "discriminant": 10,
            "status": 5,
            "max_routes": 0,
            "bytes_hex": control(10, bytes([5]) + varint(0)),
        },
        {
            "name": "route_ended_anchor_gone",
            "_comment": "RouteEnded (section 7.5): variant tag 11, reason_code 1 = anchor gone. Codes: "
            "0 unspecified, 1 anchor gone, 2 closed by policy. " + earlier,
            "discriminant": 11,
            "reason_code": 1,
            "bytes_hex": control(11, bytes([1])),
        },
    ]


def main() -> None:
    doc = route_admission()
    (ROOT / "route_admission_v1.json").write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    anchor = bytes.fromhex(doc["anchor_seal"]["sealed_hex"])
    locator = bytes.fromhex(doc["locator_seal"]["sealed_hex"])
    path = ROOT / "control.json"
    corpus = json.loads(path.read_text(encoding="utf-8"))
    new = control_entries(anchor, locator)
    names = {v["name"] for v in new}
    corpus["vectors"] = [v for v in corpus["vectors"] if v["name"] not in names] + new
    path.write_text(json.dumps(corpus, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
