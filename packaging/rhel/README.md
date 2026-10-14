# Fedora / RHEL: authselect guidance

> **Status: untested.** This guidance was written against the
> documented `authselect(8)` / `authselect-profiles(5)` formats and the
> vendor profiles authselect ships (notably `with-fingerprint`). It has
> **not** been run on a live Fedora or RHEL system — none was
> available. Try it on a disposable machine first.

## The one rule

On Fedora/RHEL, **authselect owns `system-auth`** (and `password-auth`,
`fingerprint-auth`, …). It regenerates `/etc/pam.d/system-auth` and
friends from profile templates every time a profile is selected or
changed. Editing `/etc/pam.d/system-auth` directly therefore does not
stick: the next `authselect select`, feature change, or authselect
update overwrites it. All changes below are made to a **custom
authselect profile**, never to `/etc/pam.d` files.

## What ships here

[`face-auth`](face-auth) is a small standalone PAM stack in the shape
of authselect's `fingerprint-auth`:

```
#%PAM-1.0
auth sufficient pam_zdr.so
auth required pam_deny.so
```

It is *imaginary* in the sense that nothing installs it anywhere by
itself: it becomes real only as a template file inside a custom
authselect profile (see below), from which authselect generates the
corresponding stack. In that form it serves the same role as
`fingerprint-auth`: a device-specific substack that a service can run
as its own conversation, ending in `pam_deny.so` when the face check
does not succeed. Note it is a *complete* substack, not a drop-in for
the shared stack — the shared-stack route below is what reaches
`sudo`/polkit.

## Route A: face auth in the shared stack (reaches sudo/polkit)

`sudo`, polkit, login, and most services on Fedora/RHEL include
`system-auth` or `password-auth`, so putting `pam_zdr.so` in those two
templates of a custom profile is what enables face auth for them.

1. See which vendor profile is active, and base the custom one on it
   (`local` below; use `sssd`, `winbind`, … if that is what
   `authselect current` reports):

   ```sh
   authselect current
   sudo authselect create-profile local --base-on local --symlink-meta
   ```

   `--symlink-meta` symlinks only the meta files (`README`,
   `REQUIREMENTS`); the PAM templates are real copies under
   `/etc/authselect/custom/local/`, yours to edit. Or skip authselect
   and copy the vendor profile directory you use into
   `/etc/authselect/custom/` by hand.

2. In the custom profile's `system-auth` **and** `password-auth`
   templates, add the zdr line just before `pam_unix.so`, using the
   conditional-with-feature pattern authselect's own profiles use for
   `with-fingerprint`. The smallest diff:

   ```diff
    auth        required    pam_env.so
    auth        required    pam_faildelay.so delay=2000000
   +auth        sufficient  pam_zdr.so    {include if "with-face"}
    auth        sufficient  pam_unix.so {if not "without-nullok":nullok}
    auth        required    pam_deny.so
   ```

   (Shown against the current `local` vendor template; column
   alignment and surrounding lines in your base profile may differ.
   Keep the added line's shape — `auth`, control, module,
   `{include if "with-face"}` — and match the surrounding alignment.) Face failure is then simply
   ignored by the `sufficient` control and authentication falls
   through to the password in `pam_unix.so`.

   The unconditional form used inside the standalone device stacks,

   ```
   auth [success=done default=bad] pam_zdr.so
   ```

   belongs in a `face-auth`-style substack where `pam_deny.so`
   follows it (as in authselect's `fingerprint-auth` template). Do
   not paste that form inline ahead of `pam_unix.so` in the shared
   stack; the `sufficient … {include if "with-face"}` form above is
   the one that leaves the password fallback untouched.

3. Select the custom profile with the feature on, then check what
   authselect generated before logging anything else out:

   ```sh
   sudo authselect select custom/local with-face
   authselect check
   authselect current
   ```

   (`authselect enable-feature with-face` does the same toggle on an
   already-selected profile. Features are discovered from the profile
   templates themselves, so `with-face` becomes known once the
   `{include if "with-face"}` lines exist.)

## Route B: the standalone `face-auth` stack

Drop this directory's `face-auth` file into the custom profile
directory, next to its `system-auth` template. On the next
`authselect select`, authselect generates a matching `face-auth`
stack. Services written to run a separate device conversation — the
way `fingerprint-auth` is consumed — can then include `face-auth`,
while `sudo`/polkit and everything else keep using Route A's shared
stack. Shipping both routes in one custom profile is fine.

## Safety, before either route

1. Keep a **root shell open** the whole time and work in a second
   terminal.
2. **Test first with `pamtester`.** Only select a profile containing
   `pam_zdr.so` after a `pamtester` service test passes for your user
   — while that root shell is still open.
3. Verify from the second terminal that face acceptance works *and*
   that declining/failing the face check falls back to a password.
   Only then close the spare root shell.
4. If anything looks wrong, re-select the stock profile
   (`sudo authselect select local` — or your previous profile) from
   the root shell; do not patch `/etc/pam.d` files by hand.
