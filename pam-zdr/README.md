# pam-zdr

PAM module (`pam_zdr.so`, cdylib) for zdr face authentication. It never
captures a face itself and never captures anything without explicit consent:
it asks the `zdrd` daemon over the system bus and only an approved request
reaches the daemon's capture step.

## Wire contract (frozen)

System bus, name `org.zdr.Authenticator`, object path
`/org/zdr/Authenticator`, interface `org.zdr.Authenticator`:

| Method | Signature | Used when |
|---|---|---|
| `BeginAuth` | `(user:s, service:s, tty:s, label:s) -> (request_id:s, channel:s)` | every attempt; `channel` is `"agent"` or `"terminal"` |
| `Respond` | `(request_id:s, approved:b) -> ()` | terminal channel only (PAM runs as uid 0) |
| `AwaitConsent` | `(request_id:s) -> outcome:s` | agent channel; outcome is `"approved"`, `"denied"`, or `"expired"` |
| `CaptureVerify` | `(request_id:s) -> (matched:b, reason:s)` | only after explicit approval |
| `Cancel` | `(request_id:s) -> ()` | best-effort on any error after `BeginAuth` succeeded |

## Flow (`sm_authenticate`)

1. Read user, service, tty, and rhost. If `PAM_RHOST` is set and non-empty
   (or unreadable), return `PAM_AUTH_ERR` immediately and print nothing —
   remote sessions never trigger face auth. `PAM_AUTH_ERR` (here and
   everywhere below) lets the next module in the stack, normally the
   password prompt, run.
2. Build a display label from `/proc/self/cmdline`: argv joined with spaces,
   `argv[0]` reduced to its basename (a duplicate basename in `argv[1]` is
   dropped), all control characters stripped, whitespace collapsed, capped
   at 120 characters. The label is display-only and is sanitized because it
   is rendered by the agent's GUI.
3. `BeginAuth`. On error/timeout: `PAM_AUTH_ERR` (fail closed).
   - `agent`: emit `PAM_TEXT_INFO` "Face authentication: approve in the
     popup…" (best-effort), then `AwaitConsent` with a 35 s ceiling.
   - `terminal`: ask `Use face recognition? [y/N] ` (`PAM_PROMPT_ECHO_ON`)
     through the PAM conversation. Only `y`/`yes` (any case, trimmed) is a
     yes; empty input, EOF, and conversation errors are all "no". Yes calls
     `Respond(id, true)`; anything else calls `Respond(id, false)`
     best-effort and returns `PAM_AUTH_ERR`. No capture without a yes.
   - unknown channel string: `Cancel`, `PAM_AUTH_ERR`.
4. Only on approval: `CaptureVerify`. `PAM_SUCCESS` iff `matched` is true.
   Denied/expired, unknown outcomes, and any D-Bus error (with a best-effort
   `Cancel` first) return `PAM_AUTH_ERR`.

`sm_setcred` and `acct_mgmt` return `PAM_SUCCESS`.

## Time bounds

zbus 4.1.1's blocking API has no per-call reply timeout (its calls can wait
for a reply indefinitely), so every D-Bus call runs on a worker thread and
the PAM thread waits with `recv_timeout`. Per-call ceilings: BeginAuth 5 s,
Respond 5 s, AwaitConsent 35 s, CaptureVerify 15 s, Cancel 2 s. Worst-case
D-Bus wait is therefore ≈57 s on the agent path and ≈27 s on the terminal
path, plus however long the user takes at the terminal prompt itself (like a
password prompt, that part is user-paced). On timeout the detached worker
thread may stay blocked inside zbus until the daemon/bus answers or the
process exits; the PAM-facing wait stays bounded. The module never panics on
D-Bus or conversation paths: failures are plain `PAM_AUTH_ERR` returns.

## pam-bindings 0.1.1 notes

- `PamHandle::get_user` exists; there are no dedicated `get_service` /
  `get_tty` / `get_rhost` methods. Use the generic
  `pamh.get_item::<pam::items::{Service, Tty, RHost}>()`, which wraps
  `pam_get_item` — that is what this module does.
- `pam::conv::Conv` (via `get_item::<Conv>()`) exposes one `send(style, msg)`
  helper covering both `PAM_TEXT_INFO` and `PAM_PROMPT_ECHO_ON`; the
  returned response must be copied out before the next conversation call.

## Status

Unit-tested pure pieces only: label sanitizer, yes-parser,
outcome parser, and the `decide()` mapping. **Live integration is
untested**: this module has not been run against a live PAM stack
(`pamtester`/`sudo`) or a live daemon implementing the contract above.
Do not install or enable it based on this lane alone.
