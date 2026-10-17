# zdr-enroll

A small Qt6 C++ + QML application that a normal session user runs
to enroll their own face for zdr face authentication. It is the
photo booth: one window, two camera previews (RGB and IR), five
progress dots, and one guidance line. It talks to the `zdrd`
daemon over the system bus with QtDBus — all calls are
asynchronous, so the window never freezes while the daemon (or a
password prompt, or a camera capture) takes its time.

## The flow

1. The window shows who is being enrolled (the username comes
   from `getpwuid(getuid())` in C++, never from `$USER` alone).
2. **Begin** — the app calls `BeginEnroll(user)`. For a non-root
   caller enrolling themselves, the daemon runs a polkit
   `CheckAuthorization` with user interaction, so your desktop's
   authentication agent may show a password prompt. That password
   goes to the desktop agent, never to this app. If polkit
   refuses, the daemon returns an `AccessDenied` D-Bus error and
   the app shows a plain-language error panel. The session is
   bound to this app's bus connection.
3. **Capture** (five times) — each press calls
   `EnrollCaptureWithPreview`. The returned RGB/IR PNG stills are
   shown in the two preview panes, the progress dots fill in, and
   the guidance line tells you what to fix (`too-dark` → "Too
   dark — face a light source and try again.", `duplicate-pose` →
   "Too similar — turn your head slightly and try again.", …,
   reusing the `zdrctl` wording). The Capture button stays
   disabled while a call is in flight and for one second after
   each result. `AuthFeedback` signals with
   `request_id == enroll_id` also update the guidance line during
   a capture.
4. **Finish** — when a capture returns state `ready`, the app
   automatically calls `FinishEnroll` and shows a success panel:
   how many templates were stored, plus a hint to test with
   `sudo pamtester` (e.g. `sudo pamtester -v zdr-test $USER authenticate`,
   with the service name your PAM setup uses) before relying on it.
5. **Cancel** (or closing the window) calls `CancelEnroll`
   best-effort and returns to the start state. Any error — polkit
   denied, daemon absent, camera error — lands on an error panel
   with a **Try again** button that does the same.

## Build and run (development)

With CMake (mirrors `zdr-agent/prompt/`):

```sh
cmake -S zdr-enroll -B zdr-enroll/build
cmake --build zdr-enroll/build
QT_QPA_PLATFORM=offscreen ./zdr-enroll/build/zdr-enroll zdr-enroll/zdr-enroll.qml   # smoke start
./zdr-enroll/build/zdr-enroll zdr-enroll/zdr-enroll.qml                            # real session
./zdr-enroll/build/zdr-enroll --probe                                              # library/startup probe
```

Or directly with g++ + pkg-config:

```sh
cd zdr-enroll
mkdir -p build-gpp
/usr/lib/qt6/moc main.cpp -o build-gpp/main.moc
g++ -std=c++17 -fPIC -Ibuild-gpp main.cpp -o build-gpp/zdr-enroll \
    $(pkg-config --cflags --libs Qt6Quick Qt6Gui Qt6Qml Qt6Core Qt6DBus)
QT_QPA_PLATFORM=offscreen ./build-gpp/zdr-enroll ./zdr-enroll.qml
```

`--probe` initialises `QGuiApplication` (forcing the offscreen
platform when none was selected) and exits 0; if a Qt library the
binary needs is missing, the dynamic loader fails before `main()`
runs and the probe exits non-zero.

Without an argument the QML is loaded from beside the binary
when present, else `/usr/share/zdr/zdr-enroll.qml` (the packaged
path). LayerShellQt is strictly optional (`__has_include` /
`find_package(... QUIET)`), as in the prompt host — and unlike
the prompt this is a normal session window, so it is never
attached to a layer surface.

Lint the QML with:

```sh
/usr/lib/qt6/bin/qmllint zdr-enroll.qml
```

Theming follows `zdr-prompt.qml`: the Noctalia palette is read
from `~/.config/noctalia/colors.json` (or
`$XDG_CONFIG_HOME/noctalia/colors.json`) and settings from
`settings.json` beside it, with built-in dark fallbacks for
everything. The host opts in to `QML_XHR_ALLOW_FILE_READ` so QML
can read those files, exactly like the prompt host.

## D-Bus contract consumed

System bus, `org.zdr.Authenticator` at `/org/zdr/Authenticator`,
interface `org.zdr.Authenticator`:

| Call / signal | Signature | Notes |
|---|---|---|
| `BeginEnroll` | `user:s -> enroll_id:s` | Polkit check for self-enrollment; session bound to this connection. Errors as D-Bus errors (`AccessDenied` when polkit refuses). Can block on the password prompt — called async with a 120 s timeout. |
| `EnrollCaptureWithPreview` | `enroll_id:s -> state:s, captured:i, needed:i, kind:s, rgb_png:ay, ir_png:ay` | `state` ∈ {`captured`, `rejected`, `ready`}; `kind` ∈ {`capturing`, `no-face`, `multiple-faces`, `too-dark`, `too-bright`, `duplicate-pose`, `matched`, `not-matched`, `stored`, `error`}. PNG arrays may be empty on camera error. |
| `FinishEnroll` | `enroll_id:s -> stored:i` | Called automatically when a capture returns `ready`. |
| `CancelEnroll` | `enroll_id:s -> ()` | Best-effort on Cancel, Try again, and window close. |
| `AuthFeedback` (signal) | `request_id:s, kind:s, message:s` | During enrollment `request_id` is the `enroll_id`; drives the guidance line. Other request ids are ignored. |

## Packaging note

Packaging installs this as a desktop entry (the team lead wires
the packaging at integration time). A ready draft,
`zdr-enroll.desktop`, sits in this directory: Name
`Face Enrollment (zdr)`, `Exec=zdr-enroll`,
`Categories=Settings;Security;`. The CMake install rules already
place the binary in `bin/`, the QML in `share/zdr/`, and the
desktop file in `share/applications/`; the installed `Exec`
relies on `zdr-enroll` being on `PATH`, which the `bin/` install
provides.
