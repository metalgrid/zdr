# Arch package

Builds `zdrd`, `pam_zdr.so`, and `zdr-agent` from the committed `master`
tree of this repo, and installs the YuNet and SFace models.

## Build and install

```sh
git -C /path/to/zdr commit -am "your changes"   # makepkg builds committed code only
cd packaging/arch
makepkg -si
```

The build needs network access. Cargo downloads crates, and the `ort`
crate downloads a prebuilt ONNX Runtime.

Skip tests with `makepkg --nocheck -si` when you need a faster build.

## What lands where

| File | Path |
|---|---|
| Daemon | `/usr/bin/zdrd` |
| Session agent | `/usr/bin/zdr-agent` |
| PAM module | `/usr/lib/security/pam_zdr.so` |
| Models | `/usr/share/zdr/models/` |
| D-Bus policy | `/usr/share/dbus-1/system.d/org.zdr.Authenticator.conf` |
| D-Bus activation | `/usr/share/dbus-1/system-services/org.zdr.Authenticator.service` |
| systemd unit | `/usr/lib/systemd/system/zdrd.service` |
| Agent autostart | `/etc/xdg/autostart/zdr-agent.desktop` |
| Template dir | `/var/lib/zdr/<user>/ir*.png` (mode 0700) |

The camera paths in the daemon default to this machine's by-path nodes.
Edit the unit if your cameras land elsewhere.

## First run

Follow the printed post-install steps. In short:

1. `systemctl enable --now zdrd.service`
2. Enroll 3-5 IR captures as `/var/lib/zdr/$USER/ir*.png`.
3. Re-login so the agent starts, then test with `pamtester`.
4. Only after that passes, add `auth sufficient pam_zdr.so` as the first
   line of `/etc/pam.d/sudo`, with a root shell held open.
