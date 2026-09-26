#!/usr/bin/env python3
"""Structural guard for the golden vectors.

Wire semantics are proven by the SDKs replaying these files; this script only
prevents a corrupted or malformed vector from reaching main: every *.json must
parse, every *_hex field must be lowercase hex of even length, every embedded
signed_json must itself parse, and the README must list every vector file.
"""

import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
HEX_RE = re.compile(r"^(?:[0-9a-f]{2})*$")

errors: list[str] = []


def check_hex_fields(name: str, node, path: str) -> None:
    if isinstance(node, dict):
        for key, value in node.items():
            child = f"{path}.{key}"
            if key.endswith("_hex"):
                # Optional fields (e.g. tunnel_ipv6_hex) may be null.
                if value is None:
                    continue
                # A list of ids (e.g. exit_ids_hex) holds one hex string each.
                items = value if isinstance(value, list) else [value]
                if not all(isinstance(v, str) and HEX_RE.match(v) for v in items):
                    errors.append(f"{name}: {child} is not even-length lowercase hex")
                continue
            if key == "signed_json":
                if not isinstance(value, str):
                    errors.append(f"{name}: {child} is not a string")
                    continue
                try:
                    inner = json.loads(value)
                except json.JSONDecodeError as exc:
                    errors.append(f"{name}: {child} is not valid JSON ({exc})")
                    continue
                check_hex_fields(name, inner, child)
                continue
            check_hex_fields(name, value, child)
    elif isinstance(node, list):
        for i, item in enumerate(node):
            check_hex_fields(name, item, f"{path}[{i}]")


def check_fallback_sequence(name: str, data) -> None:
    """The anti-censorship fallback sequence must be canonical: primary host
    with SNI, then each alternative host with SNI, then the primary host
    without SNI. No alternative is ever tried without SNI."""
    primary = data.get("primary_host")
    alts = data.get("alternative_hosts")
    seq = data.get("expected_candidates")
    if not isinstance(primary, str) or not primary:
        errors.append(f"{name}: primary_host must be a non-empty string")
        return
    if not isinstance(alts, list) or not all(isinstance(a, str) for a in alts):
        errors.append(f"{name}: alternative_hosts must be a list of strings")
        return
    if not isinstance(seq, list) or not seq:
        errors.append(f"{name}: expected_candidates must be a non-empty list")
        return
    expected = (
        [{"host": primary, "sni": True}]
        + [{"host": a, "sni": True} for a in alts]
        + [{"host": primary, "sni": False}]
    )
    if seq != expected:
        errors.append(
            f"{name}: expected_candidates is not the canonical sequence "
            "(primary+SNI, each alternative+SNI, primary no-SNI)"
        )


FORUM_SID_RE = re.compile(r"^[0-9a-f]{32}$")
FORUM_HANDLE_RE = re.compile(r"^[a-z]{5}-[a-z]{5}-[a-z]{5}$")
FORUM_REQUEST_NAMES = {
    "login",
    "report_with_log",
    "report_without_log",
    "attach_with_log",
    "attach_pre_topic",
}
FORUM_MAX_TOPIC_ID = (1 << 53) - 1


def check_forum_login(name: str, data) -> None:
    """The forum wire vector must be self-consistent without any crypto:
    every request's body hash, canonical message and headers must be what
    the signing rule composes from its own inputs, a report body must be the
    compact ascending-key serialisation of its fields plus the base64 of the
    pinned gzip (which must inflate to the pinned text), and every JSON answer
    must parse. The signature bytes themselves are proven by the consumers
    (warren-connect verifies each request with its clock set to the vector
    timestamp)."""
    import base64
    import gzip
    import hashlib
    import zlib

    if data.get("version") != 1:
        errors.append(f"{name}: version must be 1")
        return
    signer = data.get("signer")
    if not isinstance(signer, dict):
        errors.append(f"{name}: signer must be an object")
        return
    for key in ("signing_key_hex", "pubkey_hex", "pubkey_ss58", "timestamp", "connect_host"):
        if key not in signer:
            errors.append(f"{name}: signer.{key} is missing")
            return
    if not str(signer["pubkey_ss58"]).startswith("wb"):
        errors.append(f"{name}: signer.pubkey_ss58 is not a Warren address")
    timestamp = signer["timestamp"]
    if not isinstance(timestamp, int):
        errors.append(f"{name}: signer.timestamp must be an integer")
        return

    requests = data.get("requests")
    if not isinstance(requests, list) or not requests:
        errors.append(f"{name}: requests must be a non-empty list")
        return
    names = [r.get("name") for r in requests]
    if len(set(names)) != len(names):
        errors.append(f"{name}: request names must be unique")
    if set(names) != FORUM_REQUEST_NAMES:
        errors.append(
            f"{name}: request names {sorted(map(str, names))} differ from the "
            f"consumer-handled set {sorted(FORUM_REQUEST_NAMES)} (extend both)"
        )
    for r in requests:
        rname = f"{name}: request {r.get('name')}"
        body = r.get("body_utf8")
        if not isinstance(body, str):
            errors.append(f"{rname}: body_utf8 must be a string")
            continue
        digest = hashlib.sha256(body.encode("utf-8")).hexdigest()
        if r.get("body_sha256_hex") != digest:
            errors.append(f"{rname}: body_sha256_hex is not sha256(body_utf8)")
        nonce = r.get("nonce_hex")
        if not isinstance(nonce, str) or len(nonce) != 32:
            errors.append(f"{rname}: nonce_hex must be 16 bytes")
        if r.get("method") != "POST" or not str(r.get("path", "")).startswith("/v1/forum/"):
            errors.append(f"{rname}: must be a POST under /v1/forum/")
        if r.get("url") != f"https://{signer['connect_host']}{r.get('path')}":
            errors.append(f"{rname}: url is not https://<connect_host><path>")
        canonical = "\n".join(
            [str(r.get("method")), str(r.get("path")), str(timestamp), str(nonce), digest]
        )
        if r.get("canonical_message") != canonical:
            errors.append(f"{rname}: canonical_message is not method/path/timestamp/nonce/hash")
        headers = r.get("headers")
        if not isinstance(headers, dict):
            errors.append(f"{rname}: headers must be an object")
            continue
        expected_headers = {
            "Content-Type": "application/json",
            "X-Warren-PubKey": signer["pubkey_ss58"],
            "X-Warren-Timestamp": str(timestamp),
            "X-Warren-Nonce": nonce,
        }
        for key, value in expected_headers.items():
            if headers.get(key) != value:
                errors.append(f"{rname}: header {key} does not echo the signing inputs")
        sig = headers.get("X-Warren-Sig")
        if not isinstance(sig, str) or len(sig) != 128 or not HEX_RE.match(sig):
            errors.append(f"{rname}: X-Warren-Sig must be 64 bytes of lowercase hex")
        if "sid" in r and not FORUM_SID_RE.match(str(r["sid"])):
            errors.append(f"{rname}: sid must be 32 lowercase hex chars")
        if "topic_id" in r:
            # An attach-logs upload: the session id, the topic (0 for a
            # pre-topic session) and the base64 of the pinned gzip, compact
            # with ascending keys, like a report body.
            topic_id = r["topic_id"]
            if not isinstance(topic_id, int) or not 0 <= topic_id <= FORUM_MAX_TOPIC_ID:
                errors.append(f"{rname}: topic_id must be an integer within a JavaScript safe integer")
            if not isinstance(r.get("log_gz_hex"), str):
                errors.append(f"{rname}: an attach request carries log_gz_hex")
            else:
                gz = bytes.fromhex(r["log_gz_hex"])
                try:
                    inflated = gzip.decompress(gz).decode("utf-8")
                except (OSError, UnicodeDecodeError, EOFError, zlib.error) as exc:
                    errors.append(f"{rname}: log_gz_hex does not inflate ({exc})")
                    inflated = None
                if inflated is not None and inflated != r.get("log_utf8"):
                    errors.append(f"{rname}: log_gz_hex does not inflate to log_utf8")
                expected = {
                    "sid": r.get("sid"),
                    "topic_id": topic_id,
                    "log_gz_b64": base64.b64encode(gz).decode("ascii"),
                }
                compact = json.dumps(expected, separators=(",", ":"), sort_keys=True)
                if body != compact:
                    errors.append(f"{rname}: body_utf8 is not the compact ascending-key attach object")
        elif "sid" in r:
            if body != json.dumps({"sid": r["sid"]}, separators=(",", ":")):
                errors.append(f"{rname}: body_utf8 is not the compact sid object")
        if "fields" in r:
            expected = dict(r["fields"])
            if "log_gz_hex" in r:
                gz = bytes.fromhex(r["log_gz_hex"])
                expected["log_gz_b64"] = base64.b64encode(gz).decode("ascii")
                try:
                    inflated = gzip.decompress(gz).decode("utf-8")
                except (OSError, UnicodeDecodeError, EOFError, zlib.error) as exc:
                    errors.append(f"{rname}: log_gz_hex does not inflate ({exc})")
                    inflated = None
                if inflated is not None and inflated != r.get("log_utf8"):
                    errors.append(f"{rname}: log_gz_hex does not inflate to log_utf8")
            compact = json.dumps(expected, separators=(",", ":"), sort_keys=True, ensure_ascii=False)
            if body != compact:
                errors.append(
                    f"{rname}: body_utf8 is not the compact ascending-key serialisation of "
                    "fields (plus log_gz_b64)"
                )

    responses = data.get("responses")
    if not isinstance(responses, dict):
        errors.append(f"{name}: responses must be an object")
        return
    check_forum_answers(name, responses)

    provider = data.get("provider")
    if not isinstance(provider, dict):
        errors.append(f"{name}: provider must be an object")
        return
    if not FORUM_HANDLE_RE.match(str(provider.get("handle"))):
        errors.append(f"{name}: provider.handle is not three proquints")
    external_id = str(provider.get("external_id"))
    if len(external_id) != 64 or not HEX_RE.match(external_id):
        errors.append(f"{name}: provider.external_id must be 32 bytes of lowercase hex")
    if not str(provider.get("forum_public_url", "")).startswith("https://"):
        errors.append(f"{name}: provider.forum_public_url must be an https origin")


def check_forum_answers(name: str, responses) -> None:
    """Every answer carries an HTTP status, a content type and a body, and a
    JSON body parses."""
    for group, entries in responses.items():
        if group.startswith("_"):
            continue
        if not isinstance(entries, dict):
            errors.append(f"{name}: responses.{group} must be an object")
            continue
        for outcome, answer in entries.items():
            if outcome.startswith("_"):
                continue
            where = f"{name}: responses.{group}.{outcome}"
            if not isinstance(answer, dict):
                errors.append(f"{where}: must be an object")
                continue
            status = answer.get("status")
            if not isinstance(status, int) or not 100 <= status <= 599:
                errors.append(f"{where}: status must be an HTTP status code")
            content_type = answer.get("content_type")
            body = answer.get("body_utf8")
            if not isinstance(content_type, str) or not isinstance(body, str):
                errors.append(f"{where}: content_type and body_utf8 must be strings")
                continue
            if content_type.startswith("application/json"):
                try:
                    json.loads(body)
                except json.JSONDecodeError as exc:
                    errors.append(f"{where}: JSON body does not parse ({exc})")


FORUM_V2_REQUEST_NAMES = {"login_bound"}
FORUM_V2_STATUSES = ["pending", "awaiting_code", "approved", "completed", "cancelled"]
FORUM_V2_CANCEL_REASONS = [
    "user_cancelled",
    "subscription_required",
    "clock_skew",
    "app_update_required",
    "code_attempts_exhausted",
]
FORUM_CODE_RE = re.compile(r"^[0-9]{6}$")
FORUM_COOKIE_RE = re.compile(r"^[0-9a-f]{64}$")


def check_forum_login_v2(name: str, data) -> None:
    """The bound-login vector must be self-consistent without any crypto: the
    approval body is the compact ascending-key object of the version and the
    sid, its hash, canonical message and headers are composed from the signing
    inputs, the cookie and the handoff URL follow their frozen shapes, and the
    approved answers carry the pinned code and, on the same-device answer
    only, the pinned handoff URL. The signature bytes and every answer are
    proven by warren-connect replaying the file through its router."""
    import hashlib

    if data.get("version") != 2:
        errors.append(f"{name}: version must be 2")
        return
    signer = data.get("signer")
    provider = data.get("provider")
    if not isinstance(signer, dict) or not isinstance(provider, dict):
        errors.append(f"{name}: signer and provider must be objects")
        return
    timestamp = signer.get("timestamp")
    host = signer.get("connect_host")
    if not isinstance(timestamp, int) or not isinstance(host, str):
        errors.append(f"{name}: signer.timestamp and signer.connect_host are required")
        return
    if not str(signer.get("pubkey_ss58")).startswith("wb"):
        errors.append(f"{name}: signer.pubkey_ss58 is not a Warren address")
    code = str(provider.get("completion_code"))
    if not FORUM_CODE_RE.match(code):
        errors.append(f"{name}: provider.completion_code must be six digits")
    if not FORUM_SID_RE.match(str(provider.get("qr_sid"))):
        errors.append(f"{name}: provider.qr_sid must be 32 lowercase hex chars")
    if not FORUM_HANDLE_RE.match(str(provider.get("handle"))):
        errors.append(f"{name}: provider.handle is not three proquints")
    if not str(provider.get("forum_public_url", "")).startswith("https://"):
        errors.append(f"{name}: provider.forum_public_url must be an https origin")

    requests = data.get("requests")
    if not isinstance(requests, list) or {r.get("name") for r in requests} != FORUM_V2_REQUEST_NAMES:
        errors.append(f"{name}: requests must be exactly {sorted(FORUM_V2_REQUEST_NAMES)}")
        return
    sid = None
    for r in requests:
        rname = f"{name}: request {r.get('name')}"
        sid = str(r.get("sid"))
        if not FORUM_SID_RE.match(sid):
            errors.append(f"{rname}: sid must be 32 lowercase hex chars")
        body = str(r.get("body_utf8"))
        if body != json.dumps({"login_version": 2, "sid": sid}, separators=(",", ":"), sort_keys=True):
            errors.append(f"{rname}: body_utf8 is not the compact ascending-key version and sid")
        digest = hashlib.sha256(body.encode("utf-8")).hexdigest()
        if r.get("body_sha256_hex") != digest:
            errors.append(f"{rname}: body_sha256_hex is not sha256(body_utf8)")
        nonce = str(r.get("nonce_hex"))
        canonical = "\n".join(["POST", "/v1/forum/login", str(timestamp), nonce, digest])
        if r.get("method") != "POST" or r.get("path") != "/v1/forum/login":
            errors.append(f"{rname}: must be POST /v1/forum/login")
        if r.get("canonical_message") != canonical:
            errors.append(f"{rname}: canonical_message is not method/path/timestamp/nonce/hash")
        if r.get("url") != f"https://{host}/v1/forum/login":
            errors.append(f"{rname}: url is not https://<connect_host><path>")
        headers = r.get("headers") or {}
        expected_headers = {
            "Content-Type": "application/json",
            "X-Warren-PubKey": signer.get("pubkey_ss58"),
            "X-Warren-Timestamp": str(timestamp),
            "X-Warren-Nonce": nonce,
        }
        for key, value in expected_headers.items():
            if headers.get(key) != value:
                errors.append(f"{rname}: header {key} does not echo the signing inputs")
        sig = headers.get("X-Warren-Sig")
        if not isinstance(sig, str) or len(sig) != 128 or not HEX_RE.match(sig):
            errors.append(f"{rname}: X-Warren-Sig must be 64 bytes of lowercase hex")

    cookie = data.get("cookie") or {}
    value = str(cookie.get("example_value"))
    if cookie.get("name") != "__Host-warren_login" or not FORUM_COOKIE_RE.match(value):
        errors.append(f"{name}: cookie must be __Host-warren_login with a 64-hex value")
    if cookie.get("example_set_cookie") != (
        f"__Host-warren_login={value}; Max-Age=300; Path=/; Secure; HttpOnly; SameSite=Lax"
    ):
        errors.append(f"{name}: cookie.example_set_cookie is not the frozen attribute set")

    handoff = data.get("handoff") or {}
    expected_handoff = f"https://{host}/handoff#sid={sid}&code={code}"
    if handoff.get("path") != "/handoff" or handoff.get("example") != expected_handoff:
        errors.append(f"{name}: handoff.example is not https://<connect_host>/handoff#sid=<sid>&code=<code>")

    states = data.get("states") or {}
    if states.get("status") != FORUM_V2_STATUSES or states.get("cancel_reasons") != FORUM_V2_CANCEL_REASONS:
        errors.append(f"{name}: states must list the frozen statuses and cancel reasons")

    responses = data.get("responses")
    if not isinstance(responses, dict):
        errors.append(f"{name}: responses must be an object")
        return
    check_forum_answers(name, responses)
    login = responses.get("login") or {}
    for outcome, handoff_expected in (("approved_same_device", True), ("approved_cross_device", False)):
        try:
            body = json.loads(login.get(outcome, {}).get("body_utf8", ""))
        except json.JSONDecodeError:
            continue
        completion = body.get("completion") or {}
        if completion.get("code") != code:
            errors.append(f"{name}: responses.login.{outcome} does not carry the pinned code")
        if handoff_expected and completion.get("handoff_url") != expected_handoff:
            errors.append(f"{name}: responses.login.{outcome} does not carry the pinned handoff URL")
        if not handoff_expected and "handoff_url" in completion:
            errors.append(f"{name}: a cross-device completion carries no handoff URL")


ANNOUNCEMENT_LEVELS = {"info", "warning", "error"}


def check_announcements(name: str, data) -> None:
    """The announcements envelope must be self-consistent without any crypto:
    the pinned preimage must be the compact serialisation of the pinned fields
    in the frozen order, its digest must match, the published document must be
    that preimage plus the signature, and every call-to-action must be an https
    link with no userinfo. The signature bytes themselves are proven by the
    consumers replaying the file (warren-contract signs the pinned
    announcements and compares)."""
    import hashlib

    if data.get("version") != 1:
        errors.append(f"{name}: version must be 1")
        return
    preimage_order = data.get("preimage_field_order")
    ann_order = data.get("announcement_field_order")
    if not isinstance(preimage_order, list) or not isinstance(ann_order, list):
        errors.append(f"{name}: preimage_field_order and announcement_field_order must be lists")
        return

    raw = data.get("canonical_preimage_utf8")
    if not isinstance(raw, str):
        errors.append(f"{name}: canonical_preimage_utf8 must be a string")
        return
    try:
        preimage = json.loads(raw)
    except json.JSONDecodeError as exc:
        errors.append(f"{name}: canonical_preimage_utf8 is not valid JSON ({exc})")
        return
    if list(preimage.keys()) != preimage_order:
        errors.append(
            f"{name}: the preimage key order {list(preimage.keys())} is not the frozen "
            f"{preimage_order} (a reorder invalidates every deployed client)"
        )
    compact = json.dumps(preimage, separators=(",", ":"), ensure_ascii=False)
    if raw != compact:
        errors.append(f"{name}: canonical_preimage_utf8 is not the compact serialisation")
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    if data.get("canonical_sha256_hex") != digest:
        errors.append(f"{name}: canonical_sha256_hex is not sha256(canonical_preimage_utf8)")
    # A pure-ASCII preimage with no & < > is reproduced byte for byte by every
    # encoder on earth, so it proves nothing: Go escapes & < > by default, and
    # Python and Jackson can emit \uXXXX where serde_json emits raw UTF-8. The
    # corpus must carry both shapes or a sibling SDK passes here and diverges
    # the first time an operator writes a Romanian body.
    if raw.isascii():
        errors.append(
            f"{name}: the pinned preimage is pure ASCII, so it cannot catch an "
            f"implementation that escapes non-ASCII"
        )
    if not any(c in raw for c in "&<>"):
        errors.append(
            f"{name}: the pinned preimage carries no & < >, so it cannot catch an "
            f"implementation that HTML-escapes them"
        )

    signer = data.get("signer")
    envelope = data.get("envelope")
    if not isinstance(signer, dict) or not isinstance(envelope, dict):
        errors.append(f"{name}: signer and envelope must be objects")
        return
    for key in ("signing_key_hex", "server_pubkey_hex"):
        if len(str(signer.get(key, ""))) != 64:
            errors.append(f"{name}: signer.{key} must be 32 bytes of lowercase hex")
    expected_preimage = {
        "version": data["version"],
        "announcements": data.get("announcements"),
        "generation": envelope.get("generation"),
        "signed_at": envelope.get("signed_at"),
        "expires_at": envelope.get("expires_at"),
        "server_pubkey_hex": signer.get("server_pubkey_hex"),
    }
    if preimage != expected_preimage:
        errors.append(f"{name}: canonical_preimage_utf8 does not carry the pinned fields")

    announcements = data.get("announcements")
    if not isinstance(announcements, list) or not announcements:
        errors.append(f"{name}: announcements must be a non-empty list")
        return
    for i, a in enumerate(announcements):
        where = f"{name}: announcements[{i}]"
        if not isinstance(a, dict):
            errors.append(f"{where}: must be an object")
            continue
        if list(a.keys()) != ann_order:
            errors.append(f"{where}: key order {list(a.keys())} is not the frozen {ann_order}")
        if a.get("level") not in ANNOUNCEMENT_LEVELS:
            errors.append(f"{where}: level must be one of {sorted(ANNOUNCEMENT_LEVELS)}")
        campaign = a.get("voucher_campaign_id")
        if campaign is not None and not isinstance(campaign, str):
            errors.append(f"{where}: voucher_campaign_id must be a string or null")
        cta = a.get("cta")
        if cta is None:
            continue
        url = str(cta.get("url", ""))
        if not url.startswith("https://"):
            errors.append(f"{where}: cta.url must be an https link")
            continue
        authority = re.split(r"[/?#]", url[len("https://"):])[0]
        if not authority or "@" in authority:
            errors.append(f"{where}: cta.url must carry a host and no userinfo")

    signed_raw = data.get("signed_json")
    if not isinstance(signed_raw, str):
        errors.append(f"{name}: signed_json must be a string")
        return
    try:
        signed = json.loads(signed_raw)
    except json.JSONDecodeError as exc:
        errors.append(f"{name}: signed_json is not valid JSON ({exc})")
        return
    if list(signed.keys()) != preimage_order + ["signature_hex"]:
        errors.append(f"{name}: signed_json is not the preimage followed by signature_hex")
    if signed.get("signature_hex") != data.get("signature_hex"):
        errors.append(f"{name}: signed_json carries a different signature than signature_hex")
    if {k: v for k, v in signed.items() if k != "signature_hex"} != preimage:
        errors.append(f"{name}: signed_json does not carry the signed preimage fields")


PF_ATTRIBUTION_TAG_ERRORS = {"bad_signature", "unsupported_version", "wrong_length"}
PF_ATTRIBUTION_ENVELOPE_ERRORS = {"unsupported_version", "unsupported_tag_version", "wrong_length"}


def check_pf_attribution(name: str, data) -> None:
    """The attribution vector must be self-consistent without any crypto: the
    tag is the concatenation of its pinned fields, the signing preimage and the
    AEAD aad are the domain-separated layouts of doc 105, the envelope is its
    version, the token and the tag, and every negative case names an outcome
    from the closed set the consumers match on. The signature and the
    ciphertext themselves are proven by warren-contract replaying the file."""
    if data.get("version") != 1:
        errors.append(f"{name}: version must be 1")
        return
    domain = str(data.get("domain_utf8", "")).encode("utf-8")
    tag = data.get("tag")
    envelope = data.get("envelope")
    if not isinstance(tag, dict) or not isinstance(envelope, dict):
        errors.append(f"{name}: tag and envelope must be objects")
        return
    try:
        version = tag["version"]
        epoch = tag["epoch"].to_bytes(8, "big")
        nonce = bytes.fromhex(tag["nonce_hex"])
        ciphertext = bytes.fromhex(tag["ciphertext_hex"])
        signature = bytes.fromhex(tag["signature_hex"])
        tag_bytes = bytes.fromhex(tag["tag_hex"])
        token = bytes.fromhex(envelope["token_hex"])
        envelope_bytes = bytes.fromhex(envelope["envelope_hex"])
    except (KeyError, TypeError, ValueError, AttributeError, OverflowError) as exc:
        errors.append(f"{name}: tag or envelope field missing or malformed ({exc!r})")
        return
    for field, value, expected in (
        ("nonce", nonce, 24),
        ("ciphertext", ciphertext, 48),
        ("signature", signature, 64),
        ("account_pubkey", bytes.fromhex(str(tag.get("account_pubkey_hex", ""))), 32),
        ("tag", tag_bytes, data.get("tag_len")),
        ("token", token, data.get("token_len")),
        ("envelope", envelope_bytes, data.get("envelope_len")),
    ):
        if len(value) != expected:
            errors.append(f"{name}: {field} is {len(value)} bytes, expected {expected}")
    header = domain + bytes([version]) + epoch
    if tag.get("aad_hex") != header.hex():
        errors.append(f"{name}: aad_hex is not domain || version || epoch BE")
    if tag.get("signing_preimage_hex") != (header + nonce + ciphertext).hex():
        errors.append(f"{name}: signing_preimage_hex is not domain || version || epoch || nonce || ciphertext")
    if tag_bytes != bytes([version]) + epoch + nonce + ciphertext + signature:
        errors.append(f"{name}: tag_hex is not version || epoch || nonce || ciphertext || signature")
    if envelope_bytes != bytes([envelope.get("version", -1) & 0xFF]) + token + tag_bytes:
        errors.append(f"{name}: envelope_hex is not version || token || tag")

    for key, allowed in (
        ("invalid_tags", PF_ATTRIBUTION_TAG_ERRORS),
        ("invalid_envelopes", PF_ATTRIBUTION_ENVELOPE_ERRORS),
    ):
        cases = data.get(key)
        if not isinstance(cases, list) or not cases:
            errors.append(f"{name}: {key} must be a non-empty list")
            continue
        names = [c.get("name") for c in cases if isinstance(c, dict)]
        if len(names) != len(cases) or len(set(names)) != len(names):
            errors.append(f"{name}: {key} entries must be objects with unique names")
        for case in cases:
            if isinstance(case, dict) and case.get("expect") not in allowed:
                errors.append(f"{name}: {key}.{case.get('name')} expects {case.get('expect')!r}, not one of {sorted(allowed)}")


TOKEN_BLINDING_SALT = b"warren/token-blinding/v1"
TOKEN_BLINDING_PURPOSES = {"browser-proxy/v1", "session/v1"}


def _hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    import hashlib
    import hmac

    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    out, block = b"", b""
    counter = 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        out += block
        counter += 1
    return out[:length]


def _emsa_pss_encode_sha384(message: bytes, salt: bytes, em_bits: int) -> bytes:
    import hashlib

    em_len = (em_bits + 7) // 8
    m_hash = hashlib.sha384(message).digest()
    h = hashlib.sha384(b"\x00" * 8 + m_hash + salt).digest()
    db = b"\x00" * (em_len - len(salt) - len(h) - 2) + b"\x01" + salt
    mask, counter = b"", 0
    while len(mask) < len(db):
        mask += hashlib.sha384(h + counter.to_bytes(4, "big")).digest()
        counter += 1
    masked = bytearray(a ^ b for a, b in zip(db, mask))
    masked[0] &= 0xFF >> (8 * em_len - em_bits)
    return bytes(masked) + h + b"\xbc"


def check_token_blinding(name: str, data) -> None:
    """The wallet-derived blinding vector is recomputed here from its own
    inputs, independently of both the TypeScript reference that produced it
    and the Rust port that replays it: the blinding keys and every slot's
    draws (HKDF-SHA256), the blinding factor (first modulus-wide draw reduced
    mod n, retried while not a unit above 1), the RSABSSA blinded message, the
    issuer's blind signature under the public key, and the finalized token."""
    import hashlib
    import math

    if data.get("version") != 1:
        errors.append(f"{name}: version must be 1")
        return
    if data.get("salt_utf8") != TOKEN_BLINDING_SALT.decode():
        errors.append(f"{name}: salt_utf8 must be {TOKEN_BLINDING_SALT.decode()!r}")
        return
    try:
        seed = bytes.fromhex(data["wallet"]["seed_hex"])
        issuer = data["issuer"]
        spki = bytes.fromhex(issuer["spki_hex"])
        n = int(issuer["modulus_hex"], 16)
        e = int(issuer["public_exponent_hex"], 16)
        key_id = bytes.fromhex(issuer["token_key_id_hex"])
        keys = {k["purpose"]: bytes.fromhex(k["key_hex"]) for k in data["blinding_keys"]}
        batches = data["batches"]
    except (KeyError, TypeError, ValueError, AttributeError) as exc:
        errors.append(f"{name}: wallet, issuer or keys field missing or malformed ({exc!r})")
        return
    if len(seed) != 32:
        errors.append(f"{name}: wallet.seed_hex must be 32 bytes")
    if set(keys) != TOKEN_BLINDING_PURPOSES:
        errors.append(f"{name}: blinding_keys must cover exactly {sorted(TOKEN_BLINDING_PURPOSES)}")
    for purpose, key in keys.items():
        if key != _hkdf_sha256(seed, TOKEN_BLINDING_SALT, purpose.encode(), 32):
            errors.append(f"{name}: blinding key for {purpose} is not HKDF(seed, salt, purpose)")
    if hashlib.sha256(spki).digest() != key_id:
        errors.append(f"{name}: issuer.token_key_id_hex is not sha256(spki)")
    if bytes.fromhex(issuer["modulus_hex"]) not in spki or n.bit_length() != 2048:
        errors.append(f"{name}: issuer.modulus_hex is not the 2048-bit modulus inside the spki")
    label = str(issuer.get("context_label", "")).encode()
    issuer_name = str(issuer.get("name", "")).encode()
    quota = issuer.get("quota_per_epoch")
    if not isinstance(batches, list) or not batches:
        errors.append(f"{name}: batches must be a non-empty list")
        return
    if {b.get("purpose") for b in batches} != TOKEN_BLINDING_PURPOSES:
        errors.append(f"{name}: batches must cover every purpose")
    for batch in batches:
        where = f"{name}: batch {batch.get('purpose')}@{batch.get('epoch')}"
        key = keys.get(batch.get("purpose"))
        epoch = batch.get("epoch")
        slots = batch.get("slots")
        if key is None or not isinstance(epoch, int) or not isinstance(slots, list):
            errors.append(f"{where}: unknown purpose, or epoch or slots malformed")
            continue
        context = hashlib.sha256(label + epoch.to_bytes(8, "big")).digest()
        challenge = (
            (2).to_bytes(2, "big")
            + len(issuer_name).to_bytes(2, "big")
            + issuer_name
            + bytes([len(context)])
            + context
            + (0).to_bytes(2, "big")
        )
        digest = hashlib.sha256(challenge).digest()
        if batch.get("challenge_digest_hex") != digest.hex():
            errors.append(f"{where}: challenge_digest_hex is not the epoch challenge digest")
        if [s.get("index") for s in slots] != list(range(quota)):
            errors.append(f"{where}: slots must be indices 0..quota in order")
        for slot in slots:
            swhere = f"{where} slot {slot.get('index')}"
            try:
                index = slot["index"]
                got = {k: bytes.fromhex(v) for k, v in slot.items() if k.endswith("_hex")}
            except (KeyError, TypeError, ValueError, AttributeError) as exc:
                errors.append(f"{swhere}: malformed ({exc!r})")
                continue
            block = 0

            def draw(length: int) -> bytes:
                nonlocal block
                out = b""
                while len(out) < length:
                    info = epoch.to_bytes(8, "big") + index.to_bytes(4, "big") + block.to_bytes(4, "big")
                    out += _hkdf_sha256(key, TOKEN_BLINDING_SALT, info, 32)
                    block += 1
                return out[:length]

            nonce, salt = draw(32), draw(48)
            if got.get("nonce_hex") != nonce or got.get("salt_hex") != salt:
                errors.append(f"{swhere}: nonce or salt is not the slot's first two draws")
                continue
            first = draw(256)
            r = int.from_bytes(first, "big") % n
            while r <= 1 or math.gcd(r, n) != 1:
                r = int.from_bytes(draw(256), "big") % n
            if got.get("blinding_draw_hex") != first or got.get("blinding_factor_hex") != r.to_bytes(256, "big"):
                errors.append(f"{swhere}: blinding factor is not the third draw reduced mod n")
                continue
            token_input = (2).to_bytes(2, "big") + nonce + digest + key_id
            if got.get("token_input_hex") != token_input:
                errors.append(f"{swhere}: token_input_hex is not 0x0002 || nonce || digest || key id")
            m = int.from_bytes(_emsa_pss_encode_sha384(token_input, salt, 2047), "big")
            blinded = (m * pow(r, e, n)) % n
            if got.get("blinded_hex") != blinded.to_bytes(256, "big"):
                errors.append(f"{swhere}: blinded_hex is not EMSA-PSS(token_input) * r^e mod n")
            sig = int.from_bytes(got.get("blind_signature_hex", b""), "big")
            if pow(sig, e, n) != blinded:
                errors.append(f"{swhere}: blind_signature_hex does not verify under the issuer key")
            authenticator = (sig * pow(r, -1, n)) % n
            if got.get("token_hex") != token_input + authenticator.to_bytes(256, "big"):
                errors.append(f"{swhere}: token_hex is not token_input || blind_signature * r^-1 mod n")


ROUTE_ANCHOR_INFO = b"warren/route-anchor/v1"
ROUTE_LOCATOR_INFO = b"warren/route-locator/v1"


def check_route_admission(name: str, data) -> None:
    """Recomputes the route admission vector from its inputs with the
    standard-library HPKE of hpke_x25519.py, independently of the generator's
    output and of every Warren implementation: the KEM key pair from the
    signing seed, both seals from their ephemeral ikm, the associated data,
    the derived identifiers, that both blobs open, and that every invalid
    open is refused."""
    import hashlib

    import hpke_x25519 as hpke

    if data.get("version") != 1 or data.get("sealed_len") != 81:
        errors.append(f"{name}: version must be 1 and sealed_len 81")
        return
    suite = data.get("suite", {})
    if (suite.get("mode"), suite.get("kem_id"), suite.get("kdf_id"), suite.get("aead_id")) != (0, 0x20, 1, 3):
        errors.append(f"{name}: suite must be base mode, 0x0020, 0x0001, 0x0003")
        return
    try:
        kem = data["kem_key"]
        key_id = kem["key_id"]
        seed = bytes.fromhex(kem["signing_seed_hex"])
        secret = bytes.fromhex(data["anchor_secret_hex"])
        anchor = data["anchor_seal"]
        locator = data["locator_seal"]
        derived = data["derived"]
        serial = bytes.fromhex(anchor["serial_hex"])
        exit_id = bytes.fromhex(locator["exit_id_hex"])
        cases = data["invalid_opens"]
    except (KeyError, TypeError, ValueError, AttributeError) as exc:
        errors.append(f"{name}: field missing or malformed ({exc!r})")
        return
    if len(seed) != 32 or len(secret) != 32 or len(serial) != 32 or len(exit_id) != 16:
        errors.append(f"{name}: seed, secret and serial must be 32 bytes, the exit id 16")
        return
    info = b"warren/route-kem/v1" + bytes([key_id])
    ikm = hpke.hkdf_expand(hpke.hkdf_extract(b"", seed), info, 32)
    sk, pk = hpke.derive_key_pair(ikm)
    if kem.get("hkdf_salt_hex") != "" or kem.get("hkdf_info_hex") != info.hex():
        errors.append(f"{name}: kem_key salt must be empty and info 'warren/route-kem/v1' || key_id")
    if (kem.get("ikm_hex"), kem.get("sk_hex"), kem.get("pk_hex")) != (ikm.hex(), sk.hex(), pk.hex()):
        errors.append(f"{name}: kem_key ikm, sk or pk is not HKDF then DeriveKeyPair of the signing seed")

    def check_seal(label: str, seal: dict, info_bytes: bytes, aad: bytes) -> None:
        if seal.get("info_utf8") != info_bytes.decode() or seal.get("aad_hex") != aad.hex():
            errors.append(f"{name}: {label} info or aad is not the doc 107 layout")
        enc, ct = hpke.seal_base(pk, info_bytes, aad, secret, bytes.fromhex(seal.get("eph_ikm_hex", "")))
        sealed = bytes([key_id]) + enc + ct
        if (seal.get("enc_hex"), seal.get("ct_hex"), seal.get("sealed_hex")) != (enc.hex(), ct.hex(), sealed.hex()):
            errors.append(f"{name}: {label} enc, ct or sealed is not the HPKE seal of the anchor secret")
        if hpke.open_base(sk, enc, info_bytes, aad, ct) != secret:
            errors.append(f"{name}: {label} does not open back to the anchor secret")

    check_seal("anchor_seal", anchor, ROUTE_ANCHOR_INFO, ROUTE_ANCHOR_INFO + serial)
    check_seal("locator_seal", locator, ROUTE_LOCATOR_INFO, ROUTE_LOCATOR_INFO + exit_id)

    anchor_ref = hashlib.sha256(b"warren/route-anchor-ref/v1" + secret).digest()
    route_exit = bytes.fromhex(derived.get("exit_id_hex", ""))
    route_serial = hashlib.sha256(b"warren/route-serial/v1" + anchor_ref + route_exit).digest()
    if derived.get("anchor_ref_hex") != anchor_ref.hex() or derived.get("route_serial_hex") != route_serial.hex():
        errors.append(f"{name}: derived anchor_ref or route_serial is not the doc 107 section 6.4 hash")

    if not isinstance(cases, list) or not cases:
        errors.append(f"{name}: invalid_opens must be a non-empty list")
        return
    for case in cases:
        blob = bytes.fromhex(case.get("sealed_hex", ""))
        if case.get("open_as") == "anchor":
            info_bytes = ROUTE_ANCHOR_INFO
            aad = ROUTE_ANCHOR_INFO + bytes.fromhex(case.get("serial_hex", ""))
        elif case.get("open_as") == "locator":
            info_bytes = ROUTE_LOCATOR_INFO
            aad = ROUTE_LOCATOR_INFO + bytes.fromhex(case.get("exit_id_hex", ""))
        else:
            errors.append(f"{name}: invalid_opens.{case.get('name')} open_as must be anchor or locator")
            continue
        opened = None
        if len(blob) == 81 and blob[0] == key_id:
            opened = hpke.open_base(sk, blob[1:33], info_bytes, aad, blob[33:])
        if opened is not None:
            errors.append(f"{name}: invalid_opens.{case.get('name')} opens, it must be refused")


ROUTE_KEM_SIG_DOMAIN = b"warren/route-kem-sig/v1"
ROUTE_KEM_SIG_OUTCOMES = {"bad_signature", "expired", "unsigned", "malformed"}


def _route_kem_verdict(server_pk: bytes, block, now: int) -> str:
    """What a client concludes from one route_admission block: `ok` or the
    outcome that refuses its key, recomputed with ed25519_ref."""
    import ed25519_ref

    signed = block.get("kem_signature")
    if signed is None:
        return "unsigned"
    signature = bytes.fromhex(signed["signature_hex"])
    if len(signature) != 64:
        return "malformed"
    if now >= signed["valid_until"]:
        return "expired"
    msg = (
        ROUTE_KEM_SIG_DOMAIN
        + block["version"].to_bytes(4, "big")
        + bytes([block["kem_key_id"]])
        + bytes.fromhex(block["kem_pubkey_hex"])
        + signed["valid_until"].to_bytes(8, "big")
    )
    return "ok" if ed25519_ref.verify(server_pk, msg, signature) else "bad_signature"


def check_route_kem_signature(name: str, data) -> None:
    """Recomputes the route KEM signature vector with the standard-library
    Ed25519 of ed25519_ref.py and the HPKE of hpke_x25519.py, independently
    of the generator's signer and of every Warren implementation: the server
    key from the seed, the KEM key the same seed derives, the 68-byte message,
    the deterministic signature, the served block, and the outcome of every
    invalid case."""
    import ed25519_ref
    import hpke_x25519 as hpke

    if data.get("version") != 1 or data.get("domain_utf8") != ROUTE_KEM_SIG_DOMAIN.decode():
        errors.append(f"{name}: version must be 1 and the domain 'warren/route-kem-sig/v1'")
        return
    try:
        seed = bytes.fromhex(data["signer"]["signing_seed_hex"])
        server_pk = bytes.fromhex(data["signer"]["server_pubkey_hex"])
        kem = data["kem_key"]
        key_id = kem["key_id"]
        kem_pk = bytes.fromhex(kem["pk_hex"])
        valid_until = data["valid_until"]
        verify_at = data["verify_at"]
        served = json.loads(data["route_admission_json"])
        cases = data["invalid"]
    except (KeyError, TypeError, ValueError, AttributeError, json.JSONDecodeError) as exc:
        errors.append(f"{name}: field missing or malformed ({exc!r})")
        return
    if ed25519_ref.public_key(seed) != server_pk:
        errors.append(f"{name}: signer.server_pubkey_hex is not the Ed25519 key of the seed")
    ikm = hpke.hkdf_expand(hpke.hkdf_extract(b"", seed), b"warren/route-kem/v1" + bytes([key_id]), 32)
    if kem.get("signing_seed_hex") != seed.hex() or hpke.derive_key_pair(ikm)[1] != kem_pk:
        errors.append(f"{name}: kem_key.pk_hex is not the route KEM key the signing seed derives")
    msg = ROUTE_KEM_SIG_DOMAIN + (1).to_bytes(4, "big") + bytes([key_id]) + kem_pk + valid_until.to_bytes(8, "big")
    if data.get("message_hex") != msg.hex() or data.get("message_len") != len(msg) or len(msg) != 68:
        errors.append(f"{name}: message_hex is not domain || version BE || key_id || kem_pk || valid_until BE")
    signature = ed25519_ref.sign(seed, msg)
    if data.get("signature_hex") != signature.hex():
        errors.append(f"{name}: signature_hex is not the Ed25519 signature of message_hex under the seed")
    expected_block = {
        "version": 1,
        "kem_key_id": key_id,
        "kem_pubkey_hex": kem_pk.hex(),
        "max_routes_per_anchor": served.get("max_routes_per_anchor"),
        "exit_ids_hex": served.get("exit_ids_hex"),
        "kem_signature": {"valid_until": valid_until, "signature_hex": signature.hex()},
    }
    if served != expected_block or list(served.keys()) != list(expected_block.keys()):
        errors.append(f"{name}: route_admission_json is not the served block in its field order")
    if json.dumps(served, separators=(",", ":")) != data["route_admission_json"]:
        errors.append(f"{name}: route_admission_json is not the compact serialisation")
    if not verify_at < valid_until or _route_kem_verdict(server_pk, served, verify_at) != "ok":
        errors.append(f"{name}: the served block does not verify at verify_at")

    if not isinstance(cases, list) or not cases:
        errors.append(f"{name}: invalid must be a non-empty list")
        return
    names = [c.get("name") for c in cases if isinstance(c, dict)]
    if len(names) != len(cases) or len(set(names)) != len(names):
        errors.append(f"{name}: invalid entries must be objects with unique names")
    seen = set()
    for case in cases:
        expect = case.get("expect")
        if expect not in ROUTE_KEM_SIG_OUTCOMES:
            errors.append(f"{name}: invalid.{case.get('name')} expects {expect!r}, not one of {sorted(ROUTE_KEM_SIG_OUTCOMES)}")
            continue
        seen.add(expect)
        try:
            verdict = _route_kem_verdict(server_pk, case["block"], case["now"])
        except (KeyError, TypeError, ValueError, AttributeError) as exc:
            errors.append(f"{name}: invalid.{case.get('name')} is malformed ({exc!r})")
            continue
        if verdict != expect:
            errors.append(f"{name}: invalid.{case.get('name')} gives {verdict}, expected {expect}")
    if seen != ROUTE_KEM_SIG_OUTCOMES:
        errors.append(f"{name}: invalid must exercise every outcome {sorted(ROUTE_KEM_SIG_OUTCOMES)}")


def check_control_discriminants(name: str, data) -> None:
    """A control vector that names its discriminant must carry it as the byte
    after the marker and version, so an appended variant can never renumber
    the earlier ones unnoticed."""
    for vector in data.get("vectors", []):
        if "discriminant" not in vector:
            continue
        raw = bytes.fromhex(vector.get("bytes_hex", ""))
        if raw[:3] != bytes([0xC0, 0x03, vector["discriminant"]]):
            errors.append(f"{name}: {vector.get('name')} does not start with c0 03 and its discriminant")


def main() -> int:
    vector_files = sorted(ROOT.glob("*.json"))
    if not vector_files:
        print("FAIL: no vector files found at the repo root")
        return 1

    readme = (ROOT / "README.md").read_text(encoding="utf-8")

    for file in vector_files:
        try:
            data = json.loads(file.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            errors.append(f"{file.name}: does not parse as JSON ({exc})")
            continue
        check_hex_fields(file.name, data, "$")
        if file.name == "http_fallback_sequence.json":
            check_fallback_sequence(file.name, data)
        if file.name == "forum_login_v1.json":
            check_forum_login(file.name, data)
        if file.name == "forum_login_v2.json":
            check_forum_login_v2(file.name, data)
        if file.name == "announcements_v1.json":
            check_announcements(file.name, data)
        if file.name == "pf_attribution.json":
            check_pf_attribution(file.name, data)
        if file.name == "token_blinding_v1.json":
            check_token_blinding(file.name, data)
        if file.name == "route_admission_v1.json":
            check_route_admission(file.name, data)
        if file.name == "route_kem_signature_v1.json":
            check_route_kem_signature(file.name, data)
        if file.name == "control.json":
            check_control_discriminants(file.name, data)
        if f"`{file.name}`" not in readme:
            errors.append(f"README.md: contents table does not list {file.name}")

    if errors:
        for error in errors:
            print(f"FAIL: {error}")
        return 1

    print(f"OK: {len(vector_files)} vector files validated")
    return 0


if __name__ == "__main__":
    sys.exit(main())
