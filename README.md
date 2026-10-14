# Facial recognition authentication for linux

This is an experimental pet project for doing authentication in rust with facial recognition.
It's not ready for production, at all.

Using it for anything else than poking around and playing with it is highly discouraged.

# Building

Simple as `cargo build --release`. The daemon (`zdrd`) uses YuNet + SFace
ONNX models via `ort`; there is no dlib dependency anymore. Download the
models with `spike/scripts/download-models.sh` (or point the flags below at
your own copies).

# Running

## The daemon

Place the configuration from `dbus-1` into `/usr/share/dbus-1/system.d`.
Copy the daemon from `target/release/zdrd` somewhere, e.g. `/usr/sbin/zdrd`
Run the daemon with the model paths (everything else has defaults):

```
/usr/sbin/zdrd \
    --yunet /usr/share/zdr/face_detection_yunet_2023mar.onnx \
    --sface /usr/share/zdr/face_recognition_sface_2021dec.onnx \
    --rgb-camera /dev/v4l/by-path/pci-0000:00:14.0-usb-0:6:1.0-video-index0 \
    --ir-camera /dev/v4l/by-path/pci-0000:00:14.0-usb-0:6:1.2-video-index0 \
    --auth-dir /var/lib/zdr \
    --threshold 0.363
```

Defaults: `--rgb-camera` and `--ir-camera` as shown above,
`--auth-dir /var/lib/zdr`, `--threshold 0.363`. `--yunet` and `--sface`
are required. Cameras are captured at 640-wide (RGB MJPG 640x480, IR GREY
640x360) with warm-up frames discarded, and only after explicit consent
(see below). Capture + inference is bounded by a 15 s timeout.

### Consent protocol (system bus)

`zdrd` owns `org.zdr.Authenticator` at `/org/zdr/Authenticator`
(interface `org.zdr.Authenticator`):

- `RegisterAgent() -> ()` — the per-user GUI agent records its bus
  connection; one agent per uid, a new connection for the same uid
  replaces the old one.
- `BeginAuth(user, service, tty, label) -> (request_id, channel)` —
  root only. `channel` is `"agent"` when an agent is registered for the
  user's uid, else `"terminal"`. `request_id` is random 128-bit hex,
  valid 30 s, one pending request per user (a second call fails with
  `org.zdr.Authenticator.Error.Busy`), and a 5 s per-user cooldown
  applies after a denial. Emits the `AuthRequested` signal.
- `Respond(request_id, approved) -> ()` — only the registered agent
  connection for the request's user, or uid 0 (PAM terminal path).
- `AwaitConsent(request_id) -> outcome` — root only; waits until the
  outcome is `"approved"`, `"denied"`, or `"expired"`.
- `CaptureVerify(request_id) -> (matched, reason)` — root only, and the
  only method that ever opens a camera. Requires an approved request and
  consumes it exactly once. `reason` is one of `"match"`, `"nomatch"`,
  `"noface-ir"`, `"noface-rgb"`, `"not-approved"`, `"expired"`,
  `"camera"`, `"engine"`.
- `Cancel(request_id) -> ()` — root only.

### Interim templates (Step 5 replaces this)

Until real enrollment lands, templates are IR image files on disk:

```
/var/lib/zdr/<user>/ir*.png
```

At startup and again on every `CaptureVerify`, each `ir*.png` for that
user is embedded with SFace and cached. CaptureVerify checks only the
requesting user's templates: an IR face must be present, an RGB face
must also be present (cross-sensor gate), and the best cosine similarity
of the live IR embedding against the user's templates must be
`>= --threshold`. Unknown users and users with no usable IR templates
fail closed with reason `"nomatch"` (and no camera is opened).

## The PAM plugin

Copy `libpam_zdr.so` into `/lib/security/pam_zdr.so`
Add a line for using the authentication plugin in any services you'd like to use **zdr** with, like so:

```
auth sufficient pam_zdr.so
```

# Thanks

- [dlib](http://dlib.net/) - for the wonderful library
- [dlib face recognition](https://crates.io/crates/dlib-face-recognition) - for the easy to use bindings for dlib
- [pam-bindings](https://crates.io/crates/pam-bindings) - for the easy to use code and examples
- [zbus](https://github.com/dbus2/zbus) - for the great API
