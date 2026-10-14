# Debian / Ubuntu: pam-auth-update profile

> **Status: untested.** This profile was written against the documented
> `pam-auth-update(8)` profile format and the shape of existing Primary
> profiles shipped by Debian (SSSD, Kerberos, fingerprint).
> It has **not** been installed, enabled, or tested on a live Debian or
> Ubuntu system — none was available. Test it on a disposable machine
> before trusting it anywhere real.

## What this is

[`pam-configs/zdr`](pam-configs/zdr) is a profile for `pam-auth-update`,
the tool from `libpam-runtime` that owns the shared PAM stacks in
`/etc/pam.d/common-*` on Debian and Ubuntu. It is a *fragment for that
system*: `pam-auth-update` reads it and regenerates `common-auth`.
Nothing here edits `/etc/pam.d` files, and you should not either —
`pam-auth-update` will treat hand edits there as local modifications
and stop managing the file, or overwrite them with `--force`.

Shipped plain, with no comments inside the stanza: `pam-auth-update`
profiles are parsed as control files, so all prose lives here instead.

## For the packager

- Install the profile as **`/usr/share/pam-configs/zdr`** (mode 0644),
  next to the PAM module itself
  (`/lib/<triplet>/security/pam_zdr.so` on Debian/Ubuntu).
- The package must **depend on `libpam-runtime`**, which provides
  `pam-auth-update` and the profile machinery, and register the profile
  from its maintainer scripts the usual way (`pam-auth-update --package`
  on configure, `pam-auth-update --remove zdr` before the module is
  removed — see `pam-auth-update(8)` and `dh_installpam`).

## For the admin

The profile is deliberately **not** enabled by default
(`Default: no`). Face auth is opt-in, per machine, after testing:

1. Keep a **root shell open** for the whole procedure, and work from a
   second terminal. A broken PAM stack can lock you out of `sudo`.
2. **Test first with `pamtester`.** Only enable this profile after a
   `pamtester` service test against `pam_zdr.so` passes for your user
   (face accepted when it should be, denied or consent refused when it
   should be) — while that root shell is still open.
3. Enable it:

   ```sh
   sudo pam-auth-update          # interactive: tick "Face authentication (zdr, ...)"
   sudo pam-auth-update --enable zdr   # non-interactive equivalent
   ```

4. In the still-open second terminal, verify `sudo` works both ways:
   face accepted, and face failure/decline falling back to a password
   prompt. Only then close the spare root shell.

To turn it off again: `sudo pam-auth-update --disable zdr`.

## What enabling it does

`pam-auth-update` merges enabled Primary profiles into the shared
`/etc/pam.d/common-auth` stack. Every service that includes
`common-auth` (on a typical system: `login`, `sudo`, `sshd`, display
managers, polkit agents, …) then gets face authentication as part of
its stack. There is no per-service switch in this profile — enabling
it is system-wide for those services.

The two lines do this:

- `pam_zdr.so` with `[success=end default=ignore]`: a successful,
  consent-approved face match ends the stack as authenticated; any
  failure is ignored, so authentication **falls through to the
  password** (`pam_unix.so`) instead of locking you out.
- `pam_localuser.so` with `[success=1 default=ignore]`: a local user
  skips the next module in the generated stack; a non-local user
  falls through to it. Which module that is depends on the other
  Primary profiles enabled on the machine, so check the generated
  `common-auth` on the test system before trusting the result.

`Auth-Initial:` repeats the pair for the first-pass stack
`pam-auth-update` generates, matching how other profiles declare it.

`Priority: 128` orders this profile among the other Primary profiles
in the generated stack; `Auth-Type: Primary` puts it in the main block
rather than the additional-modules tail.

## Why `Default: no`

Face auth depends on this machine having the cameras, daemon, agent,
and enrolled templates actually working. Enabling it automatically on
package install could surprise every `common-auth` consumer at once.
The admin who has tested on *this* hardware opts in explicitly.
