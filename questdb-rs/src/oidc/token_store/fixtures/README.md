# OIDC token-store interoperability goldens

These fixtures pin the version-1 file contract shared with the Java reference
implementation at `java-questdb-client` commit
`3423784136337132d5c8c0f9dc2f0d1e7699eb9d` (PR #52).

- `java-v1-multiscope.json` is Java `FileTokenStore` output for the multi-scope
  identity and token constructed by `multiscope_key` / `multiscope_token`.
- `native-v1-multiscope.json` is the Rust writer's output for those same values.
  JSON member order is writer-specific; the parsed documents must be equal.
- `java-v1-refresh-only.json` pins Java's file-layer handling of a document with
  only a refresh token. Both file stores can round-trip it, while both OIDC auth
  implementations reject it when adopting untrusted credentials.

The issuer is configured in the multi-scope test but is intentionally absent
from the file and identity hash: concrete endpoints, not the discovery pin, are
part of the frozen persistence identity.
