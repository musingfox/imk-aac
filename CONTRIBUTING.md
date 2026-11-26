# Contributing

## Setup

You need:

- Rust stable;
- Xcode 26 or later, for the panel's macOS 26 SDK;
- the runtime requirements in [README.md](README.md), to run end-to-end tests.

## Build and check

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo build --release
xcrun swiftc -O -target arm64-apple-macos26.0 panel/main.swift -o target/release/imk-aac-panel
```

Unit tests do not touch immurok, Bitwarden or the network.

## Try the panel alone

The panel reads one JSON request on stdin. It exits 1 on Deny, 2 when the countdown ends and 3 on bad input.

```sh
echo '{"provider":"Bitwarden","item":"example","field":"api-token","picked":false,"origin":"local","agent":"Claude Code","command":"gh api user","query":"id: example:api-token","timeout_secs":5}' | target/release/imk-aac-panel
```

## End-to-end test

The daemon needs a real touch, and immurok shows its overlay differently under launchd than from a shell. So test daemon changes in a temporary LaunchAgent:

1. Put the release `imk-aac` and `imk-aac-panel` in one scratch directory.
2. Unload your regular imk-aac LaunchAgent, so only one listener uses the pairing.
3. Load a LaunchAgent that runs the scratch binary and logs to a scratch file.
4. Touch once to unlock, then send a request with a test item:

```sh
aac run --id <test-item>:<field> --env X=password -- /bin/sh -c 'test -n "$X" && echo ok'
```

5. Check three outcomes: approved by a touch, denied with the panel's Deny, and denied when nothing is done.
6. Unload the test agent and reload your regular one.

## Commits

- Use Conventional Commits, such as `feat: …`, `fix: …` or `chore: …`.
- Keep each commit buildable, and explain why in the body.
- Stage files by path.

## Releases

1. Bump `version` in `Cargo.toml`, run `cargo build` to refresh `Cargo.lock`, and commit both as `chore: release vX.Y.Z`.
2. Tag `vX.Y.Z` and push the commit and the tag.
3. The release workflow (`.github/workflows/release.yml`) tests and builds both binaries on `macos-latest`. It publishes `imk-aac-macos-aarch64.tar.gz` and `SHA256SUMS`.

## License

Contributions are licensed under Apache-2.0. If you copy more code from bitwarden/agent-access, add it to NOTICE.
