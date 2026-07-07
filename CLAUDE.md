# warren-vectors: rules for Claude Code

Shared golden vectors for the Warren protocol and its sibling SDKs.

> Shared Warren rules (single source of truth: WarrenBrowse/warren-workspace).
> They resolve when this repo is checked out inside the workspace (mani sync);
> cloned standalone, the imports just warn harmlessly.
@../shared/rules/00-conventions.md
@../shared/rules/30-git-commits.md
@../shared/rules/40-wire-vectors.md

## Repo-specific rules

- **Never rewrite published history on `main`.** Every SDK pins this repo by
  submodule gitlink (raw SHA). A rebase or force-push orphans those pins: the
  consumers' CI then only works while GitHub keeps serving unreachable objects.
  Fix mistakes with a new commit, never by rewriting.
- **Vectors are data, not secrets, and stay synthetic.** Test keys, well-known
  BIP39 mnemonics, filler bytes, and RFC 5737 documentation IPs
  (`192.0.2.x`, `198.51.100.x`, `203.0.113.x`) only. Never embed a production
  endpoint, key, or identifier in a vector.
- **CI must stay green.** `scripts/validate_vectors.py` runs on every push and
  checks JSON well-formedness, hex-field hygiene, embedded `signed_json`
  parseability, and that the README lists every vector file. Keep it passing;
  extend it when adding a new vector shape.
