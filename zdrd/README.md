# zdrd notes (Steps 10/11/14)

## Configuration (`/etc/zdr/zdrd.toml`, Step 14)

### WARNING: RGB-only mode is not secure

Setting `require_ir = false` selects RGB-only mode. A printed photo
or a photo on a phone screen can pass in this mode. It is
convenience only, not secure authentication. The daemon prints this
warning at every start in RGB mode, and `zdrctl enroll` repeats it
and requires typing `yes` before enrolling. Keep `require_ir` at
its default (`true`) unless you accept that risk.

The daemon reads `/etc/zdr/zdrd.toml` (override with `--config`).
A missing file is fine; a present but invalid file refuses startup.
Every key is optional — see `zdrd.toml.example` in this crate.
Precedence: CLI flag > config file > built-in default. Keys:
`rgb_camera`, `ir_camera` (device path or `"auto"`), `require_ir`
(bool, default `true`), `threshold` (default 0.363), `auth_dir`
(default `/var/lib/zdr`), `yunet`, `sface` (default
`/usr/share/zdr/models/*.onnx`). With no camera configured, the
daemon auto-detects by V4L2 format scan: a device offering `GREY`
and no `MJPG` is the IR candidate, a device offering `MJPG` is the
RGB candidate, lowest by-path name wins, and the probed devices are
logged at startup. Templates carry a sensor mode (format v2, see
below); verify refuses cross-mode matching with reason `nomatch`.
`ServerInfo() -> (version, require_ir)` on the D-Bus interface is a
read-only method any uid may call; it is how `zdrctl` learns the
mode above.

## Feedback signal

`AuthFeedback(request_id, kind, message)` on `org.zdr.Authenticator`
is emitted during `CaptureVerify` (request_id = auth request id) and
during enrollment captures (request_id = enroll_id). `kind` is one of
`capturing`, `no-face`, `multiple-faces`, `too-dark`, `too-bright`,
`duplicate-pose`, `matched`, `not-matched`, `stored`, `error`, and
`message` is a short human sentence. CaptureVerify emits `capturing`
before capture and exactly one terminal kind afterwards, derived from
the unchanged `(matched, reason)` result (`match`→`matched`,
`nomatch`→`not-matched`, `noface-*`→`no-face`, anything else→`error`).
The PAM wire contract is unchanged.

## Template store v2 (v1 still readable)

`<auth-dir>/<user>/templates.bin`: magic `ZDRT`, u16 version,
one mode byte in v2 (1 = IR, 2 = RGB; v1 files have no byte and
load as IR), u32 count, then per template 128 (`EMBEDDING_DIM`,
SFace) little-endian f32. Atomic temp-file + rename writes, file mode 0600
(user dir 0700). Wrong magic/version/dimension or any size mismatch
is rejected and that user fails closed. If no `templates.bin` exists
but `ir*.png` files do, they are embedded once, `templates.bin` is
written, and the PNGs are left untouched.

## Enrollment

Root-only D-Bus methods (same sender checks as `BeginAuth`):
`BeginEnroll(user) -> enroll_id` (one session per user, 120 s
expiry, 5 captures needed), `EnrollCapture(enroll_id) -> (state,
captured, needed, kind)` with state in `captured|rejected|ready`,
`FinishEnroll(enroll_id) -> stored` (writes `templates.bin` and
reloads the daemon's in-memory templates), `CancelEnroll(enroll_id)`.

Per-capture quality gates: exactly one face in IR and in RGB, IR
mean brightness in [20, 230], and cosine < 0.995 against every
already-captured session embedding (else `duplicate-pose`). In
RGB-only mode only the RGB sensor is used: exactly one RGB face,
RGB luma brightness in [20, 230], same duplicate-pose gate, and
the templates are stored with the RGB mode marker.

## zdrctl

Second binary of this package (`src/bin/zdrctl.rs`); it contains no
camera/ONNX code and drives the daemon via zbus blocking (default
feature of the already-used zbus 5, so no dependency changes).

- `sudo zdrctl enroll [user]` — user defaults to `$SUDO_USER`;
  staged pose prompts, Enter per capture, guidance per returned
  kind, finishes with `FinishEnroll`.
- `zdrctl list [--auth-dir DIR]` — per-user counts read locally
  from `templates.bin` (default auth dir `/var/lib/zdr`).
- `zdrctl remove <user> [--auth-dir DIR]` — y/N confirm, then
  deletes `templates.bin` and the `ir*.png` templates.
- `zdrctl test <user>` — prints pamtester guidance only; live
  verify is a PAM operation, there is no daemon shortcut.

Live bus enrollment is untested (no camera/root bus in CI here);
enrollment is covered at the state-machine and store level by
`cargo test -p zdrd`.
