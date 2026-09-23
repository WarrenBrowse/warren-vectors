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
                if not isinstance(value, str) or not HEX_RE.match(value):
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
