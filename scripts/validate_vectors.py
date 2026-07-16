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
