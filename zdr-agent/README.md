# zdr-agent

Per-session agent for zdr face authentication. One instance runs in
each logged-in user's desktop session (as that user, never as root).

## What it does

`zdr-agent` connects to the **system** D-Bus and talks to the zdr
daemon using this contract:

| | |
|---|---|
| Bus name | `org.zdr.Authenticator` |
| Object path | `/org/zdr/Authenticator` |
| Interface | `org.zdr.Authenticator` |
| Method | `RegisterAgent() -> ()` |
| Signal | `AuthRequested(request_id:s, user:s, service:s, tty:s, label:s)` |
| Method | `Respond(request_id:s, approved:b) -> ()` |

On start it subscribes to `AuthRequested` and then calls
`RegisterAgent`. The daemon records the agent connection's unique
bus name and uid at that point and will only accept `Respond` from
that same connection — which is how the agent's answer is tied to
the user who was actually shown the popup.

For each request **addressed to its own user** the agent shows one
`zenity` question dialog:

- title: `Face authentication requested`
- text: the request's `service`, `user`, `tty`, and command `label`,
  one field per line
- buttons: **Approve and scan** / **Deny**
- auto-dismiss after 30 s

The result is sent back with `Respond(request_id, approved)`, and
the daemon proceeds with the face scan only on approval.

## Running it in a session (manual start, for now)

There is no autostart/packaging yet; start it by hand after logging
in:

```sh
cargo build --release   # in this directory
./target/release/zdr-agent
```

Requirements at runtime:

- a reachable system bus and the `zdrd` daemon owning
  `org.zdr.Authenticator` (the agent retries until it appears),
- `zenity` in `PATH`,
- a display (`DISPLAY`/`WAYLAND_DISPLAY`) so zenity can open a window.

Stop it with `Ctrl-C` or `kill <pid>` (SIGTERM): it exits cleanly
without approving anything.

An autostart entry (e.g. an XDG `.desktop` file or a systemd user
service) is a later packaging step.

## Fail-closed rules

The agent never approves by default. Concretely:

- **Only zenity exit code 0 approves** (the user pressed
  *Approve and scan*). Deny/close (1), timeout after 30 s (5),
  zenity errors or being killed (-1 / no exit code), and every
  other exit code all send `Respond(..., false)`.
- **Missing or failing `zenity`** → logged to stderr, request denied.
- **Requests for other users are ignored** (no popup, no response).
  "Own user" is resolved from the process's real uid via
  `getpwuid`; `$USER` is never trusted for this.
- **The `label` is untrusted display text.** Newlines/control
  characters are stripped, and it is passed to zenity as data inside
  a single `--text` argument via direct `exec` — never through a
  shell — so shell metacharacters in it are inert.
- **One popup at a time.** Requests are handled sequentially;
  duplicates of an already-seen `request_id` on the same connection
  are dropped, never re-prompted.
- **Daemon/bus down** → the agent logs to stderr and retries
  `RegisterAgent` every 2 s forever; nothing is approved while
  disconnected.
- **SIGTERM/SIGINT** → the agent exits without responding; any
  request still waiting on it is left for the daemon to time out
  and deny.

## Layout

- `src/lib.rs` — bus-independent logic, unit-tested without a bus:
  exit-code → decision mapping, popup text/argument construction
  (including hostile labels), other-user filtering, duplicate
  suppression, uid/username resolution.
- `src/main.rs` — system-bus connection, signal handling, zenity
  subprocess, reconnect loop, signal-handler setup.

## Tests

```sh
cargo test
cargo build --release
```

Both work standalone in this directory: the crate carries its own
`[workspace]` table until it is wired into the root workspace at
integration time.
