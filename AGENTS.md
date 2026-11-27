# AGENTS.md

Guidance for coding agents working in this repository. User-facing behaviour is in [README.md](README.md); the workflow for changes is in [CONTRIBUTING.md](CONTRIBUTING.md).

## Map

- `src/main.rs` holds startup and the request loop. `touch_approved` races `imk run --agent` against the panel.
- `src/bitwarden.rs` covers the vault: the boot unlock through immurok, `bw` lookups, the sync-and-retry, and the field syntax (`:field`, `:?`, `:~need`).
- `src/picker.rs` is the optional local-model field picker, an OpenAI-compatible client over `/usr/bin/curl`.
- `src/overlay.rs` makes immurok's overlay read `Bitwarden …`, using a private PATH dir that holds a `Bitwarden` symlink to `/usr/bin/true`. For the boot unlock, a second private dir links `Bitwarden` to imk-aac itself, which then execs `imk get` by absolute path; a failed check falls back to gating `imk get` directly.
- `src/panel.rs` spawns `imk-aac-panel` and maps its exit code.
- `src/requester.rs` finds the local `aac run` behind a request and its agent, through libproc and `KERN_PROCARGS2`.
- `src/storage/` reads the `aac listen` pairing in `~/.access-protocol`. It is derived from upstream; keep NOTICE accurate.
- `panel/main.swift` is the SwiftUI approval panel, one file built with `swiftc`.

## Invariants

Each of these exists for a security reason. Do not relax one without the maintainer's approval.

- Only a successful `imk run --agent` approves a request. The panel, the model picker and requester detection can only deny or inform.
- `imk`, `bw`, `curl` and the panel are run by absolute path, never through `PATH`.
- Secrets travel through environment variables or stdin, never argv. Never log a secret. The requester's command is logged at debug level only.
- From other processes, read argv, parent ids and process names only, never their environment. `KERN_PROCARGS2` returns the environment after argv: parse only the first `argc` strings and zeroize the buffer.
- The model picker accepts loopback URLs only, and an answer, after trimming quotes and whitespace, must exactly match a listed field name.
- The overlay's private dir and symlink are checked before every use, and a failed check falls back to the plain `/usr/bin/true` argv.
- Never accept a new pairing. Pairing stays with `aac listen`.

## Commands

- `cargo fmt`, `cargo clippy --all-targets -- -D warnings` and `cargo test` must all pass.
- Build the panel with `xcrun swiftc -O -target arm64-apple-macos26.0 panel/main.swift -o target/release/imk-aac-panel`. If `xcrun` cannot find an SDK, prefix it with `DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer`.

## Things only a human can verify

- Running `imk`, `aac run` or `bw` triggers the maintainer's fingerprint key or touches the real vault. Ask before you run any of them.
- immurok behaves differently under launchd: a bare `imk get` shows no overlay there. Test daemon behaviour in a LaunchAgent, not only from a shell.
- When you screenshot the panel, capture only its region (`screencapture -x -R …`). Full-screen captures include the maintainer's private windows.

## Conventions

- Commits follow Conventional Commits. Stage files by path; never use `git add -A`.
- Release commits are `chore: release vX.Y.Z`. See CONTRIBUTING.md.
- Comments explain why, never what.
