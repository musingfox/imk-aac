# imk-aac

imk-aac replaces `aac listen` from [Bitwarden Agent Access](https://github.com/bitwarden/agent-access) on macOS. Every `aac run` request is approved with a touch on an immurok fingerprint key, not by pressing `y` in a terminal. The vault is unlocked once at login, also with one touch.

## How a request flows

1. An agent runs `aac run --id <item> -- <command>`, unchanged from upstream.
2. imk-aac looks the item up with the `bw` CLI. On a miss it runs `bw sync` and looks once more.
3. It opens two prompts side by side:
   - immurok's own overlay, which reads `Bitwarden <item> › <field>`;
   - an approval panel showing the provider, item, field, the agent that asked and its command, with a countdown and a Deny button.
4. A touch on immurok approves. Deny, the countdown, or immurok's own timeout rejects without a touch.

An item that is not found is rejected without any prompt.

## Requirements

- macOS 26 or later on Apple silicon. The approval panel uses Liquid Glass.
- immurok, with `imk` at `/usr/local/bin/imk` and the Bitwarden master password stored as the API secret `imk://api/bitwarden`.
- The Bitwarden CLI at `/opt/homebrew/bin/bw`, logged in (`bw login`).
- An existing pairing made with `aac listen`. imk-aac reuses its identity and paired connections under `~/.access-protocol` and never accepts a new pairing.

The paths are fixed on purpose. A planted `imk` or `bw` earlier on `PATH` would otherwise receive the master password.

## Install

1. Download `imk-aac-macos-aarch64.tar.gz` from [Releases](https://github.com/musingfox/imk-aac/releases) and check it against `SHA256SUMS`.
2. Put both `imk-aac` and `imk-aac-panel` in the same directory, for example `~/.local/bin`. imk-aac finds the panel next to its own binary, never through `PATH`. If you symlink `imk-aac`, put the panel next to the real file.
3. Stop `aac listen` first. Both use the same identity, and running two listeners on it is untested.
4. Run imk-aac as a LaunchAgent, for example `~/Library/LaunchAgents/dev.musingfox.imk-aac.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>dev.musingfox.imk-aac</string>
  <key>ProgramArguments</key>
  <array>
    <string>/Users/YOU/.local/bin/imk-aac</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <dict>
    <key>SuccessfulExit</key>
    <false/>
  </dict>
  <key>ThrottleInterval</key>
  <integer>10</integer>
  <key>StandardOutPath</key>
  <string>/Users/YOU/Library/Logs/imk-aac.log</string>
  <key>StandardErrorPath</key>
  <string>/Users/YOU/Library/Logs/imk-aac.log</string>
</dict>
</plist>
```

5. Load it with `launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/dev.musingfox.imk-aac.plist`. When immurok's overlay asks to read `imk://api/bitwarden`, touch the key once. If immurok is not yet connected at login, imk-aac tries up to five times, ten seconds apart.

## Usage

Requests use the upstream `aac run`.

| Request | Returns |
|---|---|
| `--id <item>` | The login: username, password, TOTP, the first URI and its domain. |
| `--id <item>:<field>` | One custom field. Its value travels in the password slot, so map it with `--env VAR=password`. |
| `--id <item>:?` | The item's custom field names, comma-separated in the password slot. No values. |
| `--id <item>:~<what you need>` | A local model picks one custom field by name. This is off unless configured; see below. |

`<item>` is anything `bw get item` accepts: an id or a name. A colon with text on both sides always splits item from field, so an item whose name contains one cannot be requested whole. The protocol has no slot for custom fields ([upstream issue #160](https://github.com/bitwarden/agent-access/issues/160)), which is why a field comes back as the password.

```sh
aac run --id github:api-token --env GITHUB_TOKEN=password -- gh api user
```

### Optional: let a local model pick the field

An agent often does not know an item's field names. With `:~`, a model running on this machine sees the field names (never values) and the request text, and answers with one name. The overlay and the panel mark the field as auto-picked, and the touch is still required. The model is a convenience, not a guard: a request can talk a model into a different field, so read the panel before you touch.

Set these in the LaunchAgent's `EnvironmentVariables`:

| Variable | Meaning |
|---|---|
| `IMK_AAC_PICK_PROVIDER` | `ollama`, `llamacpp` or `lmstudio` |
| `IMK_AAC_PICK_MODEL` | The model name the provider serves |
| `IMK_AAC_PICK_URL` | Optional. Defaults: Ollama `http://127.0.0.1:11434/v1`, llama-server `http://127.0.0.1:9931/v1`, LM Studio `http://127.0.0.1:1234/v1` |

The URL must be a loopback address. Any other address turns the feature off at startup.

## Security model

- Only a touch on immurok approves. The panel can only deny.
- The master password and session reach `bw` only through environment variables and pipes, never argv or the log.
- The panel receives its request as JSON on stdin.
- The agent and command in the panel come from the local `aac run` process and its parents. A process can fake them, so they are for reading only and never affect a decision. A request with no matching local process shows as a remote device.
- From other processes imk-aac reads only argv, parent ids and process names. The kernel returns a process's environment in the same buffer as its argv; imk-aac never parses that part and wipes the buffer.

## Logs

`~/Library/Logs/imk-aac.log`, or wherever the LaunchAgent points. Set `RUST_LOG=debug` for more detail; debug lines include the requester's command.

## Limitations

- macOS on Apple silicon only.
- immurok's overlay shows only about two lines of text.
- The labels for `:?` (in the overlay and the panel) and for auto-picked fields (in the overlay) are in Chinese. The rest of the panel follows the system language: Traditional Chinese or English.
- `aac` must be installed under the file name `aac` for requester detection. A symlink with another name shows as a remote device.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE): `src/storage/` is derived from bitwarden/agent-access.
