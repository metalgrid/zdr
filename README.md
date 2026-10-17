# zdr

**zdr** — short for **здравей** (*zdravei*), Bulgarian for "hello".

This is a face unlock for Linux that says hello back only after you
say it may.

## Why this exists

I wrote the first version of this years ago as a toy: something ran
`sudo`, the camera snapped a picture, and if it was my face, it went
through. It worked, and it creeped me out. If I'm sitting at the
laptop anyway — and I usually am — then anything that manages to run
`sudo` gets authenticated as me, whether I wanted it or not. That's
why the project died.

This rewrite is built around fixing exactly that. Nothing scans your
face because a process asked nicely. You get a prompt first: *this
thing wants authentication — scan?* You click yes or no. Only then
does a camera open. The face is the credential; the click is the
intent, and I never want the two confused.

## So what happens when I run sudo

A window pops up telling you what's asking (service, terminal, the
command line when we can see it). You approve, glance at the camera,
done — usually in about a second. Deny it, ignore it, or let it time
out, and you get the ordinary password prompt, like zdr was never
there. There's a short grace period where the buttons don't react,
so the Enter you were already pressing in some other window can't
accidentally approve anything.

Under the hood there are four small pieces — a root daemon that owns
the cameras, a PAM module, a little session agent that shows the
prompt, and `zdrctl` for enrollment. The matching itself is YuNet +
SFace over ONNX, checked on both the normal webcam **and** the IR
camera. That second sensor matters: when I tested, a printed photo
and a phone photo both sailed through the RGB camera and both got
rejected by IR, which couldn't even find a face on them.

## What you need

- A Linux box with PAM and systemd — developed on Arch, packaged for
  it, with Debian/RHEL PAM fragments in the tree.
- A normal webcam, and ideally an IR camera (the Windows Hello kind,
  showing up as a greyscale V4L2 device). RGB-only mode exists, but
  read the honesty section below before enabling it.
- Optionally a TPM 2.0, if you want your keyring/KeePass database to
  unlock after a face login (more in the guide).

## Get it running

The full walk-through — install, enroll, test safely, then wire up
`sudo` and polkit — lives in
[`docs/manual-setup.md`](docs/manual-setup.md). Please actually
follow the "test first, root shell open" part; PAM files are the one
place where a typo can ruin your afternoon. The short version:

```sh
cd packaging/arch && makepkg -si
sudo systemctl enable --now zdrd.service
sudo zdrctl enroll
```

If you want the guts — the consent protocol, the D-Bus contract, why
things are the way they are — that's
[`docs/architecture.md`](docs/architecture.md).

## Honest limits

- This authenticates *a live face sufficiently like yours, with your
  consent*. A close lookalike or an identical twin should be assumed
  to pass. Strangers and photographs don't.
- RGB-only mode is a convenience feature, not security. A phone
  photo beats it. The daemon will shout about this in the logs, and
  it's saying it here too.
- It's experimental security software that I happen to use every
  day. No audit, no warranty, and the password fallback is always
  there by design — zdr is a faster door, not the only door.

## Building from source

```sh
cargo build --release --workspace
cargo test --workspace
```

Models aren't vendored; the packaging fetches them from the OpenCV
zoo with pinned hashes. The QtQuick prompt is optional — without Qt
the agent falls back to a script run or notification buttons.

## Thanks

YuNet and SFace from the OpenCV zoo for being small, fast, and
permissively licensed; `ort` for painless ONNX Runtime from Rust;
`zbus` for the D-Bus API; and `pam-bindings`, which taught me a
memorable lesson about reading the source of your dependencies
(it's documented in ours, with love).

## License

MIT. Models keep their own licenses (YuNet MIT, SFace Apache-2.0).
