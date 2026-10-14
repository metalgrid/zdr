# Packaging

Per-distro packaging and PAM integration for zdr. The PAM fragments
here are inputs for each distro's own profile system, which owns
regenerating the live configuration — none of them edits `/etc/pam.d`
files, and neither should you (see the distro notes for why).

> **Status: untested off Arch.** The Debian and RHEL fragments were
> written against the documented `pam-auth-update` and `authselect`
> formats, with no live Debian/Ubuntu or Fedora/RHEL system available
> to test them on. Treat both as drafts to validate on a disposable
> machine. The Arch package is the one in daily use.

## Arch Linux — hand edit

[`arch/`](arch/) — the `PKGBUILD`, systemd/D-Bus units, and install
notes. PAM integration is a documented **hand edit**, and stays that
way: after testing with `pamtester`, with a root shell held open, add
this one line as the first auth line of `/etc/pam.d/sudo`:

```
auth sufficient pam_zdr.so
```

Full walk-through in [`arch/README.md`](arch/README.md).

## Debian / Ubuntu — pam-auth-update profile

[`debian/`](debian/) — a `pam-auth-update` profile
([`debian/pam-configs/zdr`](debian/pam-configs/zdr)) that a package
installs to `/usr/share/pam-configs/zdr`. `pam-auth-update` owns the
shared `common-auth` stack; the admin opts in with
`pam-auth-update --enable zdr`. The profile defaults to off. Details
in [`debian/README.md`](debian/README.md).

## Fedora / RHEL — authselect custom profile

[`rhel/`](rhel/) — guidance plus a standalone `face-auth` stack
([`rhel/face-auth`](rhel/face-auth)) modelled on `fingerprint-auth`.
authselect owns `system-auth`/`password-auth`; the admin creates a
custom profile, adds a `with-face` conditional `pam_zdr.so` line to
its templates, and selects it. Never edit the generated
`/etc/pam.d/system-auth` directly — authselect overwrites it. Details
in [`rhel/README.md`](rhel/README.md).

## Security note (all distros)

Never place `pam_zdr.so` as the **only** module in a stack, and never
mark it `required`. Face auth is a convenience path with a consent
gate, not a replacement credential: a failed, declined, or
camera-less attempt must always **fall through to the password**
(`pam_unix.so` with a `sufficient`-style control, or the distro
profile system's equivalent). A stack where a face failure can lock
the user out — or where nothing but the face can get them in — is
misconfigured.
