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
| `CaptureVerify` | `(request_id:s) -> (matched:b, reason:s)` | only after explicit approval, `mode=decide` |
| `CaptureVerifyAuthtok` | `(request_id:s) -> (matched:b, reason:s, password:ay)` | only after explicit approval, `mode=authtok`; root-only, one-shot; `password` non-empty only when matched and a sealed password exists |
| `Cancel` | `(request_id:s) -> ()` | best-effort on any error after `BeginAuth` succeeded |

## Module arguments

| Argument | Meaning |
|---|---|
| *(none)*, or `mode=decide` | Default, historical behaviour: a face match alone authenticates (`PAM_SUCCESS`). |
| `mode=authtok` | A face match never authenticates by itself. On a match the module deposits the TPM-released password as `PAM_AUTHTOK` and returns `PAM_IGNORE`, leaving the decision to `pam_unix`. |

Unrelated arguments are ignored; a repeated `mode=` argument resolves to
the last occurrence. An unknown `mode=` value logs one `pam_zdr:` line and
fails closed with `PAM_AUTH_ERR` — the module never guesses a mode.

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
4. Only on approval, capture — denied/expired, unknown outcomes, and any
   D-Bus error (with a best-effort `Cancel` first) return `PAM_AUTH_ERR`:
   - `mode=decide`: `CaptureVerify`. `PAM_SUCCESS` iff `matched` is true.
   - `mode=authtok`: `CaptureVerifyAuthtok`. On `matched` with a non-empty
     password, store it as `PAM_AUTHTOK` (see below) and return
     `PAM_IGNORE`; on `matched` with an empty password (no blob enrolled),
     return `PAM_IGNORE` with no token set, so the stack prompts normally.
     If storing the token fails, fail closed with `PAM_AUTH_ERR`. On not
     matched, `PAM_AUTH_ERR`. The password is never written to stderr/logs
     (only `token set for pam_unix` metadata) and local copies are wiped.

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

## Required stack shape for `mode=authtok`

```
auth [success=ignore default=ignore] pam_zdr.so mode=authtok
auth required pam_unix.so try_first_pass
```

Do **not** write `auth sufficient pam_zdr.so mode=authtok`. That form is
wrong-but-safe: in authtok mode this module never returns `PAM_SUCCESS`
(it returns `PAM_IGNORE` after depositing the token, or `PAM_AUTH_ERR`),
and `PAM_IGNORE` from a `sufficient` module is ignored by the dispatcher,
so a face match can never short-circuit or authenticate by itself, and
the password prompt always follows. The recommended form makes the
intent explicit instead: both module outcomes are mapped to `ignore`, so
`pam_unix` always runs and is the sole decider — consuming the deposited
`PAM_AUTHTOK` via `try_first_pass` with no prompt on a face match, or
prompting normally when no token was deposited. Downstream modules that
read `PAM_AUTHTOK` (e.g. `pam_kpxcd`, `pam_gnome_keyring`, `pam_kwallet`)
then unlock exactly as in a password login, with no per-vault code in zdr.

A wrong or stale token degrades gracefully: if the login password changed
after enrollment, `pam_unix`'s `try_first_pass` attempt with the sealed
password fails and `pam_unix` then prompts for the current password as
usual, so the user logs in with the new password and only face-released
autofill is skipped until they re-enroll. The same applies when the TPM
state changed and the daemon releases nothing: no token is deposited and
the normal prompt follows.

## pam-bindings 0.1.1 notes

- `PamHandle::get_user` exists; there are no dedicated `get_service` /
  `get_tty` / `get_rhost` methods. Use the generic
  `pamh.get_item::<pam::items::{Service, Tty, RHost}>()`, which wraps
  `pam_get_item` — that is what this module does.
- Setting `PAM_AUTHTOK` needs no direct FFI and no new dependency:
  `PamHandle::set_item_str` is generic over `pam::items::Item`, and
  `items::AuthTok` (item type 6) is a `CStr` item whose `into_raw` yields
  the `const char *` `pam_set_item` expects. `pam_set_item(3)` states it
  creates a copy of the object pointed to by its argument, so the local
  `CString` is wiped and dropped as soon as the call returns.
- `pam::conv::Conv` (via `get_item::<Conv>()`) exposes one `send(style, msg)`
  helper covering both `PAM_TEXT_INFO` and `PAM_PROMPT_ECHO_ON`; the
  returned response must be copied out before the next conversation call.

## Status

Unit-tested pure pieces only: label sanitizer, yes-parser, outcome
parser, the `decide()` mapping, `mode=` argument parsing, and the
exhaustive `decide_mode()` mapping. **Live integration is untested**:
this module has not been run against a live PAM stack
(`pamtester`/`sudo`) or a live daemon implementing the contract above.
In particular, live `PAM_AUTHTOK` propagation — `pam_unix`
`try_first_pass` accepting the deposited token and downstream consumers
such as `pam_kpxcd` unlocking from it — needs the owner's `pamtester`
run with a purpose-built test service after the daemon and PAM lanes
merge. Do not install or enable it based on this lane alone.
