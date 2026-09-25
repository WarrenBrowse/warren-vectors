<p align="center">
  <img src=".github/warren-logo.svg" alt="Warren" width="130"/>
</p>

# warren-vectors

The frozen **golden vectors** for the Warren VPN client protocol: the
byte-for-byte wire contract shared by every Warren SDK (Rust, Dart,
TypeScript).

This repository is the single source of truth. It is consumed as a **git
submodule** at `vectors/` by each SDK (for example `warren-sdk-rs` and
`warren-sdk-dart`), so no SDK ever duplicates the vectors. Every SDK replays
these files to prove it stays wire-identical to the others.

Warren is a VPN by [WarrenBrowse](https://github.com/WarrenBrowse); see
[warren.ro](https://warren.ro) for the product itself.

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
| `natpmp.json` | NAT-PMP port forwarding (RFC 6886 frames, the Warren result codes, the rate-limit and credential trailers) |
| `pf_attribution.json` | port-forward attribution tag v1 (version, epoch, nonce, XChaCha20-Poly1305 ciphertext of the account pubkey, Ed25519 signature over the domain-separated preimage) and the entitlement envelope v1 carried in the NAT-PMP credential trailer, with the invalid tags and envelopes a verifier must refuse |
| `forum_login_v1.json` | forum wallet login, in-app report and attach-logs upload against warren-connect: the `X-Warren` signing inputs, the exact signed request bytes, and the provider's answer per outcome, plus the attach session's status and meta answers |
| `forum_login_v2.json` | bound forum login against warren-connect: the approval request with its explicit `login_version`, the `completion` object (one-time code, same-device handoff URL) it returns, the browser half (the `__Host-warren_login` cookie, the state poll, the confirm step, the completion) and the provider's answer per outcome |
| `token_blinding_v1.json` | wallet-derived blinding of an anonymous-token batch v1: the per-class blinding key (HKDF-SHA256 of the 32-byte wallet seed, salt `warren/token-blinding/v1`, info the class purpose `browser-proxy/v1` or `session/v1`), the per-slot byte stream and its draw order (nonce, PSS salt, blinding factor), and for each slot of three batches the blinded message, the synthetic issuer's blind signature and the finalized token. Two clients of one wallet send the same batch, which the issuer serves again |
| `announcements_v1.json` | signed launch-announcement envelope v1 (`GET /v1/announcements`): the frozen canonical preimage, its signature, and the published document. One announcement carries `&`, `<`, `>` and non-ASCII letters on purpose, so an implementation that HTML-escapes or `\uXXXX`-escapes them fails here rather than on a user's screen |

## Rules

- **A vector is a contract.** Changing a vector changes the wire format and
  requires a schema-version bump in the protocol (for example `identity/v2`).
- **Never edit a vector to make a test pass.** Fix the code under test instead.
- These files are data, not secrets: they contain test keys and sample frames,
  never a real server key or user secret.

## Validation

CI runs `scripts/validate_vectors.py` on every push and pull request. It checks
that every vector file is well-formed JSON, that every `*_hex` field is
even-length lowercase hex, that every embedded `signed_json` payload parses,
and that the Contents table above lists every vector file. Run it locally with:

```sh
python3 scripts/validate_vectors.py
```

Wire semantics are proven by the SDKs replaying these files; this script only
guards structure.

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
