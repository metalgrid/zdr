# Architecture

The technical guts. For setup instructions see
[`manual-setup.md`](manual-setup.md); for the friendly tour, the
[README](../README.md).

## Components

| Piece | Process | Owns |
|---|---|---|
| `zdrd` | root daemon (systemd, D-Bus activated) | Cameras, ONNX models, template store, consent state machine, TPM seal |
| `pam_zdr.so` | loaded into the authenticating process | PAM conversation, mode logic, token deposit |
| `zdr-agent` | one per graphical session | The consent surface (QtQuick popup, `qml6`, notification actions, or any custom front-end obeying the prompt contract in `zdr-agent/README.md`) |
| `zdrctl` | root CLI | Enrollment, password sealing, store inspection |

All cross-process traffic is one system-bus interface:
`org.zdr.Authenticator` at `/org/zdr/Authenticator`.

## The consent protocol

Invariants first, because everything else is plumbing:

- A camera opens only inside `CaptureVerify*`, only for an approved
  request, which is consumed exactly once.
- One pending request per user; 30 s TTL; a denial starts a 5 s
  cooldown; request IDs are random 128-bit hex.
- `BeginAuth`, `AwaitConsent`, `CaptureVerify*`, and `Cancel`
  accept uid 0 callers only; enrollment additionally accepts the
  polkit-authorized self path below. Caller identity comes
  from the bus daemon (`GetConnectionUnixUser` on the unique name),
  never from client-supplied fields.
- `Respond` accepts uid 0 (the PAM terminal path) or the exact
  connection that called `RegisterAgent` for that user's uid. Another
  same-user process cannot answer for you.
- The `label` (usually the caller's `/proc/self/cmdline`) is display
  text only: length-capped, control-stripped, never parsed.

Flow for one authentication:

```text
PAM ──BeginAuth(user, service, tty, label)──▶ daemon ──AuthRequested──▶ agent
PAM ──AwaitConsent(id)  (blocks)              daemon ◀──Respond(id, ok)── agent
PAM ──CaptureVerify(id) ──▶ capture RGB+IR ──▶ match? ──▶ (bool, reason)
```

Methods:

| Method | Caller | Result |
|---|---|---|
| `ServerInfo()` | anyone | `(version, require_ir)` |
| `RegisterAgent()` | session agent | records its unique name + uid |
| `BeginAuth(user, service, tty, label)` | root | `(request_id, channel)` — `agent` or `terminal` |
| `Respond(id, approved)` | agent or root | records the decision |
| `AwaitConsent(id)` | root | `approved` / `denied` / `expired` |
| `CaptureVerify(id)` | root | `(matched, reason)` |
| `CaptureVerifyAuthtok(id)` | root | `(matched, reason, password)` — password only after match *and* a re-check of the same embedding |
| `Cancel(id)` | root | drops the request |
| `EnrollPassword(user, password)` | root | seals to `<auth-dir>/<user>/password.cred` |
| `HasSealedPassword(user)` | anyone | existence only |
| `BeginEnroll(user)`, `EnrollCapture(id)`, `EnrollCaptureWithPreview(id)`, `FinishEnroll(id)`, `CancelEnroll(id)` | root, or the user themselves after a polkit check (below) | five-capture guided enrollment; the `WithPreview` variant also returns PNG stills of the judged frames |
| `TemplateInfo()` | any uid (self only) | `(count, mode, has_sealed)` for the caller's own templates |
| `VerifySelf()` | any uid (self only) | `(matched, reason, best, rgb_png, ir_png)` — one capture against the caller's own templates; never opens a camera when they have none |

Self-enrollment authorization: a non-root caller may begin an
enrollment only for their own uid, and only after the daemon gets a
polkit `CheckAuthorization` for action
`org.zdr.Authenticator.Enroll` (shipped in
`packaging/polkit/`, `auth_self`). The session binds to the caller's
unique bus name; later enrollment calls accept only that caller (or
uid 0). `TemplateInfo` and `VerifySelf` take no user argument at
all — the daemon derives the target from the caller's uid, so there
is nothing to forge. `VerifySelf` journal-logs every call
(`zdrd: VerifySelf …`) since it opens cameras for non-root callers.

Signals: `AuthRequested(id, user, service, tty, label)` and
`AuthFeedback(id, kind, message)` with kinds `capturing`, `no-face`,
`multiple-faces`, `too-dark`, `too-bright`, `duplicate-pose`,
`matched`, `not-matched`, `stored`, `error`.

Verify reasons: `match`, `nomatch`, `noface-ir`, `noface-rgb`,
`not-approved`, `expired`, `camera`, `engine`.

## Recognition pipeline

YuNet detects; five landmarks align the face to 112×112; SFace
produces a 128-float embedding; the best cosine against the user's
templates decides against `threshold`. IR enrollments match IR
captures; the store records its capture mode and cross-mode matching
is refused. Warm-up frames are discarded until frame brightness
settles (minimum 3, cap 11 per sensor — one journal line per capture
reports the count). Capture plus inference runs on a worker thread
under a 15 s deadline — zbus handlers run on an executor with no
Tokio reactor, and a past version that forgot this panicked live.
The details live in `zdrd/README.md`.

## Template store

`/var/lib/zdr/<user>/templates.bin`: magic `ZDRT`, u16 version, mode
byte (IR/RGB), u32 count, then 128 little-endian `f32` per template.
Atomic replace via temp file + rename, mode `0600` in a `0700`
directory. Corrupt or foreign files fail closed: the user simply has
no templates. Legacy `ir*.png` enrollments import once.

## The sealed password (authtok mode)

`zdrctl enroll-password` reads the password twice with echo off and
the daemon seals it with `systemd-creds encrypt --with-key=tpm2`,
bound to PCR 7 by default (`tpm_pcrs`). Release requires, in order:
a fresh approved request, a face match, and a re-check of that same
embedding against the store. Only then does the blob unseal, only
for the root PAM module, exactly once. Owned buffers are zeroed on
drop. A login-password change invalidates nothing structurally — the
stale token just fails `pam_unix` validation and the user gets a
normal prompt until re-enrollment.

## Configuration

One file, `/etc/zdr/zdrd.toml`, precedence **CLI > file > default**;
a present-but-invalid file refuses startup. Cameras default to
auto-detection by V4L2 format scan (`GREY`-only ⇒ IR, `MJPG` ⇒ RGB,
lowest by-path name wins). The full resolved configuration is logged
at every start. Annotated reference: `zdrd/zdrd.toml.example`.

## Prompt front-ends

The agent tries, in order: `$ZDR_PROMPT_CMD`, the QtQuick host
(`--probe`-verified), the `qml6` script, desktop-notification
actions, then deny. Any executable obeying the tiny contract in
`zdr-agent/README.md` (four argv fields, exit 0 = approve, optional
`status: ` lines on stdin) is a valid front-end. The reference QML
prompt reads Noctalia's `colors.json`/`settings.json` when present
and disarms all input for the first second on screen.
