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
`/usr/share/zdr/models/*.onnx`), `tpm_pcrs` (default `"7"`, see
AUTHTOK below). With no camera configured, the
daemon auto-detects by V4L2 format scan: a device offering `GREY`
and no `MJPG` is the IR candidate, a device offering `MJPG` is the
RGB candidate, lowest by-path name wins, and the probed devices are
logged at startup. Templates carry a sensor mode (format v2, see
below); verify refuses cross-mode matching with reason `nomatch`.
`ServerInfo() -> (version, require_ir)` on the D-Bus interface is a
read-only method any uid may call; it is how `zdrctl` learns the
mode above.

## AUTHTOK: TPM-sealed password release (Step 15)

What is sealed: the user's *actual login password*, sealed by
`systemd-creds` (the TPM boundary — zdrd links no TSS library) with
`--name=zdr-password --with-key=tpm2` to
`<auth-dir>/<user>/password.cred` (mode 0600, user dir 0700). The
password is fed to the child on stdin only: never in argv, the
environment, or any log line. Daemon-owned copies live in a zeroizing
buffer (`seal::SecretBytes`); that covers zdrd-owned buffers, not
allocator history or the copies zbus/DBus necessarily materialize.

TPM binding: by default the blob is bound to PCR 7 (Secure Boot
state) via `tpm_pcrs = "7"` in `zdrd.toml`. A non-empty value is a
`+`-separated PCR list (`"7+11"`). `tpm_pcrs = ""` means no PCR
binding: the `--tpm2-pcrs` flag is then *omitted*, because
systemd-creds 262 accepts an empty `--tpm2-pcrs=` at encrypt time
but the credential it produces cannot be decrypted again. With no
PCR binding the blob still only unseals on this machine's TPM, but
no longer notices Secure Boot state changes. Changing PCRs (or a
firmware/Secure Boot change that alters PCR 7) makes old blobs
unsealable: re-run `zdrctl enroll-password`.

Who may release: only a root caller of
`CaptureVerifyAuthtok(request_id) -> (matched, reason, password)`,
i.e. the root PAM module, and only bound to a fresh consent request
that was approved and is consumed exactly once, exactly like
`CaptureVerify` (reason strings are identical). The flow is:
consume request → ONE face capture+embedding → only on a match,
unseal (10 s cap, inside the same worker thread, under the 15 s
capture budget plus that cap) → re-check that same embedding
against the template store (best cosine recomputed from the
embedding, compared to the threshold; no second capture) → only
then return the password bytes, zeroizing the daemon copy before
returning. Exactly one `capturing` and one terminal `AuthFeedback`
kind are emitted per request. No match means no unseal attempt is
ever made; a release re-check that no longer passes (e.g. the
templates changed after capture) withholds the password with
reason `nomatch`. A match with no sealed blob returns `password`
empty (not an error). `EnrollPassword(user, password)` is root-only;
`HasSealedPassword(user) -> has` may be called by any uid and
reveals existence only.

Password changes: the blob is a snapshot. If the user changes their
login password, the sealed copy goes stale — face auth still
matches, the released old password is handed to `pam_unix`, which
fails it, and PAM falls back to the normal password prompt. Fix by
re-running `sudo zdrctl enroll-password` after a password change.

The honest limit (locked decision): a face match now *equals* the
password everywhere this release is wired in. Anyone who can pass
the face check (or defeat it — see the RGB-only warning above) gets
the real password released to PAM and with it everything the
password unlocks. That is the design's intent (single sign-on from
the face), not an implementation bug; enrolling a sealed password
is what opts a user into it. `sudo zdrctl remove <user>` deletes
`password.cred` along with the templates, and `zdrctl list` shows
`sealed password: yes/no` per user.

## Camera warm-up (adaptive)

Each sensor capture takes at least 3 frames, then stops as soon as
the mean brightness settles (frame-to-frame change ≤ 2.0 on the
0-255 scale), and never takes more than 11 frames per stream
(previously a fixed 10 warm-up frames were discarded plus 1 kept,
per sensor, per capture). Every capture logs one line, e.g.
`zdrd: capture ir frames=4 settle=early` (`settle=cap` when the
brightness never stabilised within 11 frames), so the effect is
visible in the journal. Streams are still started per capture:
one paired (RGB then IR) capture per `CaptureVerify`, and one
paired capture per `CaptureVerifyAuthtok`.

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
- `sudo zdrctl enroll-password [--user <name>]` — reads the login
  password twice from `/dev/tty` with echo disabled, rejects empty
  or mismatched entries, seals it via `EnrollPassword`, and verifies
  with `HasSealedPassword`.
- `zdrctl list [--auth-dir DIR]` — per-user counts read locally
  from `templates.bin` (default auth dir `/var/lib/zdr`), plus
  `sealed password: yes/no` per user by `password.cred` existence.
- `zdrctl remove <user> [--auth-dir DIR]` — y/N confirm (the prompt
  notes the sealed password goes too), then deletes
  `templates.bin`, the `ir*.png` templates, and `password.cred`.
- `zdrctl test <user>` — prints pamtester guidance only; live
  verify is a PAM operation, there is no daemon shortcut.

Live bus enrollment is untested (no camera/root bus in CI here);
enrollment is covered at the state-machine and store level by
`cargo test -p zdrd`.
