# Arch package

Builds `zdrd`, `pam_zdr.so`, and `zdr-agent` from the `master` branch
on GitHub, and installs the YuNet and SFace models.

## Build and install

```sh
cd packaging/arch
makepkg -si
```

For local development builds, makepkg builds committed code only.
Point the PKGBUILD `source` at your checkout
(`git+file:///path/to/zdr#branch=master`), commit your changes, then
build as above.

The build needs network access. Cargo downloads crates, and the `ort`
crate downloads a prebuilt ONNX Runtime.

Skip tests with `makepkg --nocheck -si` when you need a faster build.

## What lands where

| File | Path |
|---|---|
| Daemon | `/usr/bin/zdrd` |
| Session agent | `/usr/bin/zdr-agent` |
| Enrollment GUI | `/usr/bin/zdr-enroll` (+ desktop entry, `/usr/share/polkit-1/actions/org.zdr.Authenticator.policy`) |
| PAM module | `/usr/lib/security/pam_zdr.so` |
| Models | `/usr/share/zdr/models/` |
| D-Bus policy | `/usr/share/dbus-1/system.d/org.zdr.Authenticator.conf` |
| D-Bus activation | `/usr/share/dbus-1/system-services/org.zdr.Authenticator.service` |
| systemd unit | `/usr/lib/systemd/system/zdrd.service` |
| Agent user service | `/usr/lib/systemd/user/zdr-agent.service` (enable with `systemctl --user enable --now zdr-agent.service`) |
| Template dir | `/var/lib/zdr/<user>/templates.bin` (dir `0700`, file `0600`) |
| Config | `/etc/zdr/zdrd.toml` |

Cameras auto-detect by V4L2 format at daemon start. Pin paths in
`/etc/zdr/zdrd.toml` only if detection picks wrong.

## First run

Follow the printed post-install steps. In short:

1. `sudo systemctl enable --now zdrd.service`
2. `systemctl --user enable --now zdr-agent.service`
3. Enroll with `zdr-enroll` (GUI) or `sudo zdrctl enroll`, then test
   with the app's **Test my face** or with `pamtester`.
4. Only after that passes, add `auth sufficient pam_zdr.so` as the first
   line of `/etc/pam.d/sudo`, with a root shell held open.

The full walk-through lives in [`../../docs/manual-setup.md`](../../docs/manual-setup.md).
