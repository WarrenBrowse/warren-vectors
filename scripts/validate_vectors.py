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
