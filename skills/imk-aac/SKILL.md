---
name: imk-aac
description: Run a command that needs a password, API token or sudo by injecting the secret from the user's Bitwarden vault with `aac run`; the user approves each request with one touch on their immurok fingerprint key. Use when a script or CLI needs a credential (API token, sudo password, login, a custom field) and would otherwise prompt the user or need the secret pasted into chat.
---

`aac run` asks the user's Mac for one vault item over an end-to-end encrypted channel. On the Mac, imk-aac shows an approval panel beside immurok's overlay, and only a touch on the fingerprint key releases the secret.

## The one rule

Only `aac run`. It puts the secret in the child process's environment and never on stdout. Never run `aac connect` or anything with `--output json`: they print the secret into the tool output, and from there into the transcript and session memory. Inside `aac run`, never echo, log or write the variable. The one exception is a field-name listing (`:?` below), which carries names and no values.

Scripts you write read secrets from environment variables. They never prompt with `read -s` or similar: there is no tty, and a prompt is exactly what this skill replaces.

## Asking for a secret

| Request | You get, in the `password` slot unless noted |
|---|---|
| `--id <item>` | The login: `username`, `password`, `totp`, `uri`, `domain`. |
| `--domain <host>` | The login whose URI matches the host. |
| `--id <item>:<field>` | One custom field's value. |
| `--id <item>:?` | The item's custom field names, comma-separated. No values. |
| `--id <item>:~<what you need>` | A local model picks one custom field. Off unless the user configured it. |

`<item>` is a vault item id or name. Ask the user for it when you do not know it.

```bash
aac run --id github --env GH_TOKEN=password -- gh release list
aac run --id cloudflare:api-token --env CLOUDFLARE_API_TOKEN=password -- wrangler deploy
aac run --id cloudflare:? --env FIELDS=password -- sh -c 'printf "%s\n" "$FIELDS"'
```

When you do not know a custom field's name, list the names with `:?` first, then ask for the one you need by its exact name.

## sudo

Claude Code's Bash has no tty, so plain `sudo` fails. Feed the login password to `sudo -S` on stdin:

```bash
aac run --id <item> --env SUDO_PW=password -- sh -c 'printf "%s\n" "$SUDO_PW" | sudo -S -p "" <command>'
```

`sudo -S` consumes stdin, so the command after it cannot read stdin. Each call is its own request and its own touch.

## Before the call

1. Tell the user a fingerprint request is coming and what it is for. The panel shows your agent name and the command after `--`, so keep that command readable.
2. The user has 30 seconds to touch. Give the Bash call a timeout of at least 2 minutes.
3. `aac` must be invoked under the name `aac`. A wrapper or symlink with another name makes the panel show the request as coming from a remote device.

## When it fails

Every refusal reaches you as a failed `aac run`. Tell them apart by what the user saw:

| What happened | Do |
|---|---|
| The user did not touch within 30 seconds | Ask the user, then retry once. |
| The user pressed Deny in the panel | Stop. Retry only if the user asks. |
| No panel appeared at all | The item or field is not in the vault, or imk-aac is not running. Confirm the item with the user, or list fields with `:?`. |
| Exit 5 | The pairing's fingerprint does not match. Stop and tell the user. |

Never pair a new device yourself, and never ask the user for a PSK: pairing is done once by the user with `aac listen`, and imk-aac refuses new pairings.
