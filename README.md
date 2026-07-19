# warren-vectors

The frozen **golden vectors** for the Warren VPN client protocol: the
byte-for-byte wire contract shared by every Warren SDK (Rust, Dart, TypeScript,
Python, Kotlin, Swift, Java).

This repository is the single source of truth. It is consumed as a **git
submodule** at `vectors/` by each SDK (for example `warren-sdk-rs` and
`warren-sdk-dart`), so no SDK ever duplicates the vectors. Every SDK replays
these files to prove it stays wire-identical to the others.

## Contents

| File | Pins |
|---|---|
| `identity.json` | BIP39 to Ed25519 derivation, SS58 `wb...` addresses, request signing |
| `multihop_frame.json` | HPKE multihop frame (postcard) |
| `multihop_frame_v2.json` | `/v2` post-quantum multihop frame (postcard, X-Wing hybrid seal) |
| `xwing_kem.json` | X-Wing (X25519 + ML-KEM-768) KEM known-answer vectors (draft-connolly-cfrg-xwing-kem) |
| `pq_hpke_seal_v2.json` | `/v2` post-quantum HPKE seal: X-Wing encaps + sealed frame + signed ML-KEM exit descriptor |
| `control.json` | control `/v3` codec (marker `0xC0 0x03`, DAITA capability echo) |
| `pop.json` | proof-of-possession |
| `relays.json` | signed relay list |
| `multihop_directory.json` | signed multi-hop directory (PKI chain: root, operational, per-node) |
| `http_v1.json` | client-facing `/v1` HTTP API DTO shapes (`warren_contract::dto`) |
| `http_fallback_sequence.json` | canonical anti-censorship HTTP fallback attempt sequence |

## Rules

- **A vector is a contract.** Changing a vector changes the wire format and
  requires a schema-version bump in the protocol (for example `identity/v2`).
- **Never edit a vector to make a test pass.** Fix the code under test instead.
- These files are data, not secrets: they contain test keys and sample frames,
  never a real server key or user secret.

## Versioning

Consumers pin a specific commit of this repository through their submodule
gitlink, so a vectors change never silently reaches a consumer. Bump the
submodule pointer deliberately when adopting a new contract revision.

**Never rewrite published history** (rebase, force-push, amend of a pushed
commit): consumers pin commits by SHA, and a rewritten `main` orphans every
pinned gitlink, leaving their CI dependent on GitHub still serving unreachable
objects.

## License

AGPL-3.0-or-later, matching the Warren engine.
