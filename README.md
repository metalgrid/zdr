# zdr

**zdr** — from **здравей** (*zdravei*), "hello" in Bulgarian.

Face authentication for Linux that asks before it looks. A PAM module,
a system daemon, and a session agent run a short ceremony for every
authentication: something requests auth, a prompt asks *you* whether
to scan, and only after your explicit approval does the camera open,
capture paired RGB + IR frames, and match your face. No silent
`snap, compare` moment exists anywhere in the design.

> **Status:** experimental security software, in daily use on the
> author's machine (`sudo` and polkit). It fails closed to the
> password prompt everywhere, but it has had no independent security
> audit. Test with a root shell held open before trusting it.

## How it works

| Component | Runs as | Job |
|---|---|---|
| `zdrd` | root, systemd service | Owns the cameras and the ONNX models. The only process that ever captures a face. Serves `org.zdr.Authenticator` on the system bus. |
| `pam_zdr.so` | inside the authenticating process | Drives one consent-gated check per PAM attempt. Never touches a camera. |
| `zdr-agent` | your session | Shows the consent prompt. Only its registered connection may answer for you. |
| `zdrctl` | root, via `sudo` | Enrollment and administration. |

One authentication:

1. A PAM stack reaches `pam_zdr.so`. Remote sessions are rejected at
   once; a local camera never opens for `sshd`.
2. The daemon creates a one-shot request (30 s life, one per user,
   a short cooldown after each denial) and picks a consent channel:
   the session agent if registered, otherwise a terminal `[y/N]`
   prompt through the PAM conversation.
3. You approve or deny. Input stays inert for the first second, so a
   keystroke already in flight cannot become an approval. Deny,
   timeout, EOF, and Ctrl-C all mean no — and no camera has opened.
4. After approval the daemon captures RGB (640×480) and IR (640×360),
   requires exactly one face in each, and compares the IR embedding
   against *only that user's* templates.
5. The result returns to PAM. Every failure shape — denial, no
   match, no camera, dead daemon — falls through to the password
   prompt.

Recognition is YuNet (detection) + SFace (128-float embeddings) over
ONNX Runtime via the `ort` crate. On the development machine: ~4 ms
detection, ~12 ms full pipeline, about 105 MB resident with models
loaded. No GPU, no cloud, no telemetry.

## Design rules

- **Consent before capture, always.** The camera light never turns on
  for a request you have not seen. A background process running
  `sudo` gets a prompt on your screen, not your face.
- **Two sensors or it does not count.** A phone or printed photo
  passes RGB matching easily (measured) and fails the IR sensor.
  Both must see one face, at the same time.
- **Per-user templates.** A request for user A is only ever compared
  against A's templates. Unknown users fail closed.
- **The password is the floor.** Face auth is a convenience path in
  front of `pam_unix`, never a replacement and never the only way in.
- **Embeddings, not photos.** The template store holds floats, under
  `/var/lib/zdr/<user>/`, root-owned, mode `0600`.

## Requirements

- Linux with PAM, systemd, and a system D-Bus.
- A webcam (RGB) and, for the real security story, a dedicated IR
  camera exposing a `GREY` V4L2 format — the Windows Hello class of
  hardware. Without IR, `require_ir = false` enables an RGB-only mode
  that photos defeat; the daemon, config, and enrollment all warn
  loudly if you turn it on.
- Optional: TPM 2.0 for the sealed-password mode below.

## Quick start (Arch)

Full walk-through, including testing and recovery, is in
[`docs/manual-setup.md`](docs/manual-setup.md). The short form:

```sh
cd packaging/arch && makepkg -si
sudo systemctl enable --now zdrd.service
sudo zdrctl enroll          # five guided captures
# test against a throwaway PAM service first, root shell open:
sudo pamtester -v zdr-test $USER authenticate
```

Then add one line as the first auth line of `/etc/pam.d/sudo`:

```text
auth sufficient pam_zdr.so
```

Debian/Ubuntu and Fedora/RHEL use their PAM profile systems instead
of hand edits; see [`packaging/README.md`](packaging/README.md).

## Configuration

`/etc/zdr/zdrd.toml` (CLI flags override it):

- `rgb_camera`, `ir_camera` — device paths; absent or `"auto"` means
  detect by V4L2 format scan at startup.
- `require_ir` — default `true`. `false` is the RGB-only downgrade.
- `threshold` — cosine match bar, default `0.363`. Single-user
  machines should raise it (the author runs `0.6`; his live scores
  sit above 0.95).
- `auth_dir`, `yunet`, `sface` — store and model paths.
- `tpm_pcrs` — PCR binding for the sealed password, default `"7"`.

An annotated example ships as `zdrd/zdrd.toml.example` and installs
as `/etc/zdr/zdrd.toml` from the Arch package.

## The authtok mode (keyring-friendly logins)

`sudo zdrctl enroll-password` seals your login password with
`systemd-creds` against the TPM. With the module placed as

```text
auth [success=ignore default=ignore] pam_zdr.so mode=authtok quiet
auth required pam_unix.so try_first_pass
```

a face match releases the sealed password into `PAM_AUTHTOK`,
`pam_unix` validates it, and token consumers (KeePass daemons,
keyrings) unlock exactly as after a typed login. In this mode a face
match never authenticates by itself. `quiet` suppresses the PAM info
message that would make modal polkit agents (e.g. Noctalia's panel)
cover the consent popup.

## Repository layout

| Path | Contents |
|---|---|
| `zdrd/` | The daemon and `zdrctl`. |
| `pam-zdr/` | The PAM module (`pam_zdr.so`). |
| `zdr-agent/` | The session consent agent and the QtQuick prompt (themeable; reads Noctalia's palette when present). Prompt backends are pluggable. |
| `dbus-1/` | The system-bus policy for `org.zdr.Authenticator`. |
| `packaging/` | Arch `PKGBUILD`, Debian `pam-auth-update` profile, RHEL authselect guidance. |
| `docs/` | The manual setup guide. |
| `spike/` | The Phase 0 engine benchmark that selected YuNet + SFace. Historical; still handy for capturing enrollment photos. |
| `data/` | Legacy dlib models from the project's first incarnation. Unused by current code. |

## Building from source

```sh
cargo build --release --workspace
cargo test --workspace
```

The `ort` crate downloads a prebuilt ONNX Runtime at build time, and
the model files come from the OpenCV zoo (the Arch package fetches
them as checked sources; `spike/scripts/download-models.sh` does the
same for manual builds). The optional QtQuick prompt host
(`zdr-agent/prompt/main.cpp`) needs Qt 6 Quick; without it the agent
falls back to `qml6` or desktop-notification actions.

## Security summary

zdr authenticates *a live face sufficiently like yours, with explicit
consent, in front of two sensors*. That is strong against photos,
screens, strangers, and unattended auth requests. It is not a depth
sensor, it has no certified anti-spoofing, and a close lookalike —
above all an identical twin — should be assumed able to pass. Face
data never leaves the machine. If that threat model does not fit
yours, keep the password and treat this as a very polite doorbell.

## Thanks

- [YuNet](https://github.com/opencv/opencv_zoo/tree/main/models/face_detection_yunet)
  and [SFace](https://github.com/opencv/opencv_zoo/tree/main/models/face_recognition_sface)
  from the OpenCV zoo, for small, fast, permissively licensed models.
- [`ort`](https://github.com/pykeio/ort), the ONNX Runtime bindings.
- [`zbus`](https://github.com/dbus2/zbus), for the D-Bus API.
- [`pam-bindings`](https://crates.io/crates/pam-bindings) — used with
  care, and with one hard-won workaround documented in the source.

## License

MIT. The model files carry their own licenses (YuNet MIT, SFace
Apache-2.0) and are downloaded, never vendored.
