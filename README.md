# Facial recognition authentication for linux

This is an experimental pet project for doing authentication in rust with facial recognition.
It's not ready for production, at all.

Using it for anything else than poking around and playing with it is highly discouraged.

# Building

Install `dlib` from your system's package manager.
Archlinux users can install `dlib` from AUR.

Simple as `cargo build --release`.

# Running

## The daemon

Place the configuration from `dbus-1` into `/usr/share/dbus-1/system.d`.
Copy the data files from `data/` somewhere accessible, like `/usr/share/zdr/`
Copy the daemon from `target/release/zdrd` somewhere, e.g. `/usr/sbin/zdrd`
Run the daemon with a bunch of parameters:

```
/usr/sbin/zdrd -r 0.4 \
    --ddb /usr/share/zdr/mmod_human_face_detector.dat \
    --pdm /usr/share/zdr/shape_predictor_68_face_landmarks.dat \
    --rdb /usr/share/zdr/dlib_face_recognition_resnet_model_v1.dat \
    --camera /dev/video0 \
    --auth-dir /path/to/your/images
```

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
