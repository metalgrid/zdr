# Manual setup guide

How zdr fits together, and how to wire it into `sudo`, polkit, and
login stacks by hand. On Arch the PAM edits below are manual on
purpose (Arch packages never rewrite `/etc/pam.d`). On Debian/Ubuntu
and Fedora/RHEL the distro profile systems own those files; use the
fragments in [`packaging/`](../packaging/README.md) instead of editing
them directly — the concepts in this guide still apply.

## The pieces

| Component | Runs as | Job |
|---|---|---|
| `zdrd` | root, systemd service | Owns the cameras and models. The only process that ever captures a face. Serves `org.zdr.Authenticator` on the system bus. |
| `pam_zdr.so` | inside the authenticating process (root) | Asks the daemon for a consent-gated face check. Never touches a camera. |
| `zdr-agent` | your session | Shows the consent prompt (Approve / Deny). Registered with the daemon; only its connection may answer. |
| `zdrctl` | root (via sudo) | Enrollment and administration: faces, sealed password, listings. |

## How one authentication flows

1. A PAM stack reaches `pam_zdr.so`. The module reads the PAM user and
   rejects remote sessions (`PAM_RHOST` set) immediately.
2. The module calls `BeginAuth` on the daemon. The daemon creates a
   one-shot request (30 s life, one per user) and picks a channel:
   **agent** if `zdr-agent` is registered for your uid, else
   **terminal**.
3. Consent happens *before* any camera opens:
   agent channel — the popup asks Approve/Deny (input is inert for the
   first second, so a stray keystroke cannot approve);
   terminal channel — PAM asks `Use face recognition? [y/N]`.
   Deny, timeout, EOF, and Ctrl-C all mean no.
4. Only after approval does the daemon capture: RGB + IR frames, one
   face required in each, SFace embedding of the IR face compared
   against *that user's* templates only.
5. The module maps the result by mode (below) and the stack proceeds.
   Every failure path falls through to the password prompt.

## The two module modes

- `pam_zdr.so` (decide mode, the default): face match returns
  `PAM_SUCCESS`. Mark it `sufficient` so a match ends the stack and a
  failure falls through to the password.
- `pam_zdr.so mode=authtok`: a match never authenticates by itself.
  Instead the daemon releases a TPM-sealed copy of the login password,
  the module stores it as `PAM_AUTHTOK` and returns `PAM_IGNORE`, and
  `pam_unix` with `try_first_pass` validates it. Downstream token
  consumers (kpxcd, gnome-keyring, kwallet) then unlock exactly as in
  a typed login. This mode must **not** be marked `sufficient`.

## Install (Arch package)

```sh
cd packaging/arch
makepkg -si
sudo systemctl enable --now zdrd.service
```

The daemon reads `/etc/zdr/zdrd.toml`. Cameras auto-detect by pixel
format (a `GREY`-only device is IR, an `MJPG` device is RGB); pin
paths in the config only if detection picks wrong. Set
`threshold = 0.6` for a single-user machine: the 0.363 default is a
publishing-dataset value, and real users typically score far above it.

**`require_ir = false` is a security downgrade, not a feature.** RGB-only
matching accepts printed and phone photos (measured: both pass RGB
easily, both fail IR). Treat it as a doorbell, not a lock.

## Enroll

Two front-ends, same daemon machinery:

- **GUI:** run `zdr-enroll` (or launch "Face Enrollment (zdr)").
  It opens on your status (template count and mode, sealed password
  yes/no), asks polkit for your password once before enrolling
  (your desktop's normal auth panel), then takes five guided
  captures with live RGB/IR previews and plain-language guidance.
  **Test my face** runs one capture against your own templates and
  shows the judged stills with the match score. **Re-enroll**
  replaces the current set and asks for confirmation first.
- **CLI:** the same flow from a terminal:

```sh
sudo zdrctl enroll            # five guided captures, quality gated
sudo zdrctl list              # root-only store: /var/lib/zdr/<user>/
sudo zdrctl enroll-password   # optional: seal the login password to the TPM
sudo zdrctl remove <user>     # delete templates and any sealed password
```

The agent is a systemd **user** service (it refuses to run as
root or as a system service). Enable it once per user:
`systemctl --user enable --now zdr-agent.service`.

## Test before you touch a real service

Keep a root shell (`sudo -s`) open for this whole section.

```sh
sudo tee /etc/pam.d/zdr-test >/dev/null <<'EOF'
#%PAM-1.0
auth sufficient pam_zdr.so
auth required pam_unix.so
EOF
sudo pamtester -v zdr-test $USER authenticate
```

Expect: popup, approve, scan, success — then a deny run that lands on
the password prompt. A stack whose only module is `sufficient
pam_zdr.so` can *fake* success on module failure; that is what the
`required pam_unix.so` line prevents. Never ship a sufficient-only
stack.

## Enable for sudo

Back up first, then put ours as the **first** auth line:

```text
#%PAM-1.0
auth		sufficient	pam_zdr.so
auth		include		system-auth
account		include		system-auth
session		include		system-auth
session		optional	pam_systemd.so class=none
```

```sh
cp /etc/pam.d/sudo /etc/pam.d/sudo.bak   # restore point, root shell open
sudo -k; sudo true                        # in a NEW terminal
```

## Enable for polkit

Polkit reads `/etc/pam.d/polkit-1` if present, else the vendor file
(`/usr/lib/pam.d/polkit-1`). Create the local override:

```text
#%PAM-1.0
auth       sufficient   pam_zdr.so quiet
auth       include      system-auth
account    include      system-auth
password   include      system-auth
session    include      system-auth
```

Test with `pkexec whoami` from a graphical terminal. Deleting the
file restores the vendor default instantly.

Why `quiet`: modal polkit agents (Noctalia's panel, for one) open a
full-screen modal on the first PAM conversation message. Our
`PAM_TEXT_INFO` hint would summon that modal on top of our own popup
and make it unclickable. `quiet` sends nothing during consent, so the
popup is the only surface; the agent's panel still appears afterwards
if a password is needed. Use `quiet` anywhere a modal agent or
greeter renders the conversation.

Note: prompts that authenticate *as root* (`auth_admin`) check root's
templates, find none, and fall through to the password. That is by
design.

## Login greeters and keyrings (authtok mode)

Where a token consumer must unlock at login (kpxcd, keyrings), use:

```text
auth [success=ignore default=ignore] pam_zdr.so mode=authtok quiet
auth required pam_unix.so try_first_pass
```

Requires a sealed password (`zdrctl enroll-password`). If the login
password changes later, the stale seal simply fails validation and the
greeter prompts normally until you re-enroll the password.

## Troubleshooting

| Symptom | Likely cause | Check |
|---|---|---|
| `Error.Busy: a request is already pending` | An earlier request is still inside its 30 s life | Wait, retry. Nothing is stuck. |
| A few seconds of refusals after a deny | 5 s post-denial cooldown | Working as designed. |
| Terminal `[y/N]` instead of the popup | No agent registered for your uid | `pgrep -x zdr-agent`; daemon log shows `agent registered`. |
| `zdrctl list`: permission denied | The store is root-only (0700) | `sudo zdrctl list`. |
| Camera opens but no match | Look at the journal settle lines and the verify reason | `journalctl -u zdrd -f`, watch `frames=`/`settle=` and `reason=`. |
| Everything falls back to password | Daemon down, or PAM process not root (plain `pamtester` without sudo) | `systemctl status zdrd`; rerun with `sudo pamtester`. |
| Polkit panel covers the popup | Missing `quiet` argument on the polkit line | See the polkit section above. |

## Security summary

Face match alone decides only in decide mode, and only behind an
explicit consent action, a dual-sensor presence gate, and per-user
templates. Embeddings and sealed passwords live under `/var/lib/zdr`
(mode 0700/0600, root-owned) and embeddings are never photos. The
system authenticates *a live face sufficiently like yours, with
consent*. Against photos and strangers that is strong; against a
close lookalike or identical twin, your password remains the better
lock — which is why every failure shape in this guide ends at one.
