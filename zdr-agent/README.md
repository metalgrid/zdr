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
| Signal | `AuthFeedback(request_id:s, kind:s, message:s)` (display only) |
| Method | `Respond(request_id:s, approved:b) -> ()` |

On start it subscribes to `AuthRequested` and then calls
`RegisterAgent`. The daemon records the agent connection's unique
bus name and uid at that point and will only accept `Respond` from
that same connection — which is how the agent's answer is tied to
the user who was actually shown the prompt.

For each request **addressed to its own user** the agent asks for
consent through the first available prompt backend (below), and
sends the result back with `Respond(request_id, approved)`. The
daemon proceeds with the face scan only on approval. Nothing about
the prompt is a hard Qt dependency: Qt is one optional front-end.

After `RegisterAgent` the agent also subscribes to `AuthFeedback`
on the same system-bus connection, handled on a dedicated thread
so it can never block the consent loop. Feedback whose
`request_id` matches the request whose prompt subprocess is
currently running is forwarded to that subprocess's stdin (see
the optional status protocol below); all other feedback — and all
feedback while the notification backend is showing, which has no
stdin sink — is logged as one sanitized stderr line. Feedback is
display only: it never calls daemon methods and never changes
`Respond` behaviour or the consent flow.

## Prompt backends

For every request the agent walks this chain and logs to stderr
which backend was chosen and which were skipped, and why:

1. **Custom command** — `ZDR_PROMPT_CMD`, an absolute path to any
   executable obeying the [prompt executable contract](#prompt-executable-contract).
   If it is set but fails to *run*, the agent logs it and falls
   through to the next backend. (A command that runs and exits
   non-zero has answered: deny.)
2. **Qt host binary** — `zdr-prompt`, resolved from
   `ZDR_PROMPT_BIN`, then `/usr/lib/zdr/zdr-prompt`, then `PATH`.
   Each existing candidate is first probed with `--probe`
   (initialises a `QGuiApplication`, prints nothing, exits 0;
   3 s cap). A missing Qt library makes the dynamic loader fail
   the probe before `main()` runs, so a broken host is skipped,
   never fatal. The first candidate that passes the probe shows
   the QtQuick prompt.
3. **`qml6` script** — if `qml6` (override: `ZDR_QML_BIN`) is on
   `PATH` and the QML file exists (resolution order below), the
   same QML runs directly under the QML runtime. Development
   fallback; the host binary is preferred when installed.
4. **Desktop notification** — built into the agent, no toolkit
   needed. Over a lazily opened **session** bus connection the
   agent checks `org.freedesktop.Notifications.GetCapabilities`
   for `actions` support (skipped if absent), then calls `Notify`
   with app name `zdr`, summary `Face authentication requested`, a
   body with the service/user/tty/label lines, actions
   `approve`/`deny` ("Approve and scan"/"Deny"), critical urgency,
   and a 30 s expiry. An `approve` action approves; `deny`, any
   notification close, a timeout (bounded by the remaining 35 s
   request budget), or any error denies.
5. **Nothing available → deny** (fail closed). PAM then falls
   through to the password prompt as usual.

`ZDR_PROMPT=qt|qml|notify|none` forces a single front-end (or, with
`none`, disables prompting entirely: every request is denied via
the agent channel and PAM falls back to password). Unset it for
the automatic chain above.

### Prompt executable contract

Third-party front-ends (e.g. a future GTK prompt) only need to
obey this contract and be pointed to by `ZDR_PROMPT_CMD` (or
installed as a `zdr-prompt` host):

- **argv** is exactly `[service, user, tty, label]` — four separate
  arguments, never a shell. All four are sanitized single-line
  strings, but treat the label as untrusted display text anyway.
- **Exit 0 = approve.** Any non-zero exit denies. The agent kills
  the executable after 35 s and denies, so front-ends must
  self-time-out at 30 s (deny) rather than wait forever.
- **Never print secrets.** Fields may appear in logs; print
  nothing sensitive to stdout/stderr.
- **Optional stdin status protocol.** While the executable runs,
  the agent may write lines to its stdin in the form
  `status: <message>` (human-readable live feedback from the
  daemon, e.g. a face-capture hint), each preceded by a companion
  `status-kind: <kind>` line where `<kind>` is one of `capturing`,
  `no-face`, `multiple-faces`, `too-dark`, `too-bright`,
  `duplicate-pose`, `matched`, `not-matched`, `stored`, `error`.
  Both lines are single-line sanitized text. A front-end may
  display `status:` lines (optionally tinting by kind) or ignore
  stdin entirely — ignoring it has no effect on the exit-code
  contract. The bundled Qt host implements this; the same QML run
  under bare `qml6` ignores stdin and keeps its default status.

The bundled QtQuick front-end is additionally invoked as
`zdr-prompt <qml path> <service> <user> <tty> <label>` and under
`qml6` as `qml6 <qml path> -- <service> <user> <tty> <label>`
(the `--` stops the runtime from loading fields as QML files).

### QML and host resolution order

`zdr-prompt.qml` is resolved (first existing file wins):

1. `ZDR_PROMPT_QML`
2. `/usr/share/zdr/zdr-prompt.qml`
3. `./zdr-agent/prompt/zdr-prompt.qml` relative to the working
   directory (workspace-root dev runs)
4. `prompt/zdr-prompt.qml` under the crate's source directory
   (compile-time path; `cargo run` from anywhere)
5. `../../zdr-agent/prompt/zdr-prompt.qml` relative to the
   executable's directory (`target/{debug,release}` dev builds)

## The QtQuick prompt

`prompt/zdr-prompt.qml` is a self-contained 440×320 QtQuick window
(title `zdr-prompt`) showing "Face authentication requested", the
service/user/tty lines, the label in quotes when non-empty, a
status line under the request details (default
“Look at the camera…”), a 30 s countdown bar, and
**Approve and scan** / **Deny** buttons.
Enter/Return approves, Escape denies, the countdown reaching zero
denies, and closing the window denies. Exit code 0 approves,
1 denies — the contract above. The C++ host feeds the status line
from its stdin (`status: ` / `status-kind: ` lines, above) into
the QML `statusText`/`statusKind` properties on the GUI thread;
the status is tinted primary for `matched`, error colour for
`not-matched`/`error`/`no-face`, and secondary text colour
otherwise (mirroring `feedback_tone` in `src/lib.rs`).

`prompt/main.cpp` is a minimal optional C++ host for it. If
layer-shell-qt headers are available at build time
(`__has_include(<LayerShellQt/Window.h>)`), the window is attached
to the **Overlay** layer with on-demand keyboard interactivity and
no anchors (compositor-centred); otherwise the identical binary
shows a plain window. `prompt/CMakeLists.txt` does the same check
via `find_package(LayerShellQt QUIET)`.

### Noctalia theme

At startup the QML loads, via `file://` XMLHttpRequest:

- `$XDG_CONFIG_HOME/noctalia/colors.json` (fallback
  `~/.config/noctalia/colors.json`): `mSurface` → window
  background, `mOnSurface` → main text, `mOnSurfaceVariant` →
  secondary text, `mSurfaceVariant` → card background,
  `mPrimary`/`mOnPrimary` → the approve button, `mError`/`mOnError`
  → deny emphasis, `mOutline` → borders, `mHover` → hover.
- `settings.json` next to it: `general.radiusRatio` scales a 12 px
  corner-radius base, and `ui.fontDefault` becomes the font family.

`XDG_CONFIG_HOME`/`HOME` are discovered from `/proc/self/environ`
(plain QML has no getenv); reading the files needs
`QML_XHR_ALLOW_FILE_READ=1` in the child environment, which both
the agent and the C++ host set automatically. Every value has a
built-in dark fallback, so with no Noctalia config — or corrupt
JSON, or file access unavailable — the prompt still renders
sanely; theme loading can never blank or hang the window.
`ZDR_PROMPT_SECONDS` shortens the countdown for manual testing
(default stays 30).

### Hyprland note

The QtQuick prompt is a normal Wayland window (unless the host was
built with layer-shell-qt, in which case it is an overlay surface
and window rules do not apply). On Hyprland a plain window may be
**tiled** like any other. To float and centre it instead, add an
optional window rule matching the title `zdr-prompt`, e.g.:

```
windowrule = float on, match:title zdr-prompt
windowrule = center on, match:title zdr-prompt
```

(Adjust to your Hyprland version's window-rule syntax if needed.)
Without such a rule the prompt still works — it just opens as a
tiled window.

## Running it in a session (manual start, for now)

There is no autostart/packaging yet; start it by hand after logging
in:

```sh
cargo build --release -p zdr-agent   # from the workspace root
./target/release/zdr-agent
```

Requirements at runtime:

- a reachable system bus and the `zdrd` daemon owning
  `org.zdr.Authenticator` (the agent retries until it appears),
- at least one prompt backend: a `ZDR_PROMPT_CMD` executable,
  Qt6 (`qt6-declarative`, for the host/`qml6`), or a notification
  server with action support on the session bus. With none of
  these, every request is denied and PAM falls back to password,
- a display (`DISPLAY`/`WAYLAND_DISPLAY`) for the Qt front-ends.

Stop it with `Ctrl-C` or `kill <pid>` (SIGTERM): it exits cleanly
without approving anything.

An autostart entry (e.g. an XDG `.desktop` file or a systemd user
service) is a later packaging step.

### Development runs

Run the QML alone (auto-denies after the test countdown):

```sh
QML_XHR_ALLOW_FILE_READ=1 ZDR_PROMPT_SECONDS=5 \
  qml6 zdr-agent/prompt/zdr-prompt.qml -- sudo "$USER" tty1 "test label"
echo $?   # 1 = denied at countdown end
```

Build the host with plain Qt (no layer-shell needed) and probe it:

```sh
g++ -std=c++17 -fPIC zdr-agent/prompt/main.cpp -o /tmp/zdr-prompt \
  $(pkg-config --cflags --libs Qt6Quick Qt6Gui Qt6Qml Qt6Core)
/tmp/zdr-prompt --probe && echo probe-ok
ZDR_PROMPT_SECONDS=5 /tmp/zdr-prompt \
  zdr-agent/prompt/zdr-prompt.qml sudo "$USER" tty1 "test label"
```

(or `cmake -S zdr-agent/prompt -B build-prompt && cmake --build build-prompt`).
Then point the agent at the dev files:

```sh
ZDR_PROMPT_BIN=/tmp/zdr-prompt \
ZDR_PROMPT_QML="$PWD/zdr-agent/prompt/zdr-prompt.qml" \
  ./target/release/zdr-agent
```

## Fail-closed rules

The agent never approves by default. Concretely:

- **Only prompt exit code 0 approves** (the user pressed
  *Approve and scan*, or invoked the notification's approve
  action). Deny/close, the 30 s self-timeout, prompt errors or
  being killed (-1 / no exit code), every other exit code, and
  the agent's own 35 s kill-on-timeout all send
  `Respond(..., false)`.
- **Executable backends that fail to run** (missing binary, failed
  host probe, spawn error) are logged and the chain falls through;
  if no backend can serve the request, the request is denied.
- **Requests for other users are ignored** (no popup, no response).
  "Own user" is resolved from the process's real uid via
  `getpwuid`; `$USER` is never trusted for this.
- **The `label` is untrusted display text.** Newlines/control
  characters are stripped, and every field reaches the prompt as
  its own `exec` argument — never through a shell — so shell
  metacharacters in it are inert.
- **One popup at a time.** Requests are handled sequentially;
  duplicates of an already-seen `request_id` on the same connection
  are dropped, never re-prompted.
- **Feedback is display only.** `AuthFeedback` is routed by exact
  `request_id` match to the running prompt (or logged); unknown or
  stale feedback can never approve, deny, or extend a prompt.
- **Daemon/bus down** → the agent logs to stderr and retries
  `RegisterAgent` every 2 s forever; nothing is approved while
  disconnected.
- **SIGTERM/SIGINT** → the agent exits without responding; any
  request still waiting on it is left for the daemon to time out
  and deny.

## Layout

- `src/lib.rs` — bus-independent logic, unit-tested without a bus:
  exit-code → decision mapping, prompt argument construction
  (including hostile labels), backend selection and mode parsing,
  QML/host path resolution, other-user filtering, duplicate
  suppression, uid/username resolution, feedback routing
  (active-request match vs log-only), `status: ` line formatting,
  and the feedback kind → tone mapping.
- `src/main.rs` — system-bus connection, signal handling
  (including the separate `AuthFeedback` thread sharing the
  connection), prompt subprocess spawning/probing/waiting with
  piped stdin, backend chain, reconnect loop, signal-handler setup.
- `src/notify.rs` — desktop-notification backend (session bus,
  `org.freedesktop.Notifications`).
- `prompt/zdr-prompt.qml` — the QtQuick prompt (Noctalia-themed).
- `prompt/main.cpp`, `prompt/CMakeLists.txt` — optional QtQuick
  host binary with compile-time-optional layer-shell support and
  the stdin → QML status bridge.

## Tests

From the workspace root:

```sh
cargo test -p zdr-agent
cargo build -p zdr-agent --release
qmllint zdr-agent/prompt/zdr-prompt.qml   # if qmllint is available
```
