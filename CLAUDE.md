# warren-vectors: rules for Claude Code

Shared golden vectors for the Warren protocol and its sibling SDKs.

> **This repo carries no `@` import on purpose.** It is checked out both as a
> workspace sibling AND as a `vectors/` submodule inside `warrenguard`,
> `warren-core`, `warren-sdk-rs`, `warren-sdk-dart` and `warren-sdk-ts`. A
> relative import would resolve only in the sibling case and point at a
> non-existent path in the five others. The shared Warren rules reach a session
> here through the parent repo's `CLAUDE.md` and the workspace one, which are
> loaded in every case.

## Repo-specific rules

- **Never rewrite published history on `main`.** Every SDK pins this repo by
  submodule gitlink (raw SHA). A rebase or force-push orphans those pins: the
  consumers' CI then only works while GitHub keeps serving unreachable objects.
  Fix mistakes with a new commit, never by rewriting.
- **Vectors are the wire contract, so a vector is never edited to make a test
  pass.** A mismatch is a real wire-format regression: fix the code. Changing a
  format means adding a new schema version (for example `identity/v2`) rather
  than mutating the existing one.
- **Vectors are data, not secrets, and stay synthetic.** Test keys, well-known
  BIP39 mnemonics, filler bytes, and RFC 5737 documentation IPs (`192.0.2.x`,
  `198.51.100.x`, `203.0.113.x`) only. Never embed a production endpoint, key, or
  identifier in a vector.
- **Adding a vector NAME breaks the consumers until they handle it.**
  `warrenguard` and `warren-sdk-rs` replay `vectors/control.json` through a
  `match` on the vector name whose fallback arm is
  `panic!("unknown control vector name")`. That is the intended behaviour: it is
  what stops a stale corpus pin from silently dropping golden vectors for wire
  features already shipped. Advance the submodule pin in the consumers and add
  the arm, in the order described by the `warren-sibling-pins` skill (the
  submodule moves FIRST).
- **CI must stay green.** `scripts/validate_vectors.py` runs on every push and
  checks JSON well-formedness, hex-field hygiene, embedded `signed_json`
  parseability, and that the README lists every vector file. Keep it passing;
  extend it when adding a new vector shape.
- **English only**, and never an em-dash or en-dash, in every file here (shared
  Warren conventions).
