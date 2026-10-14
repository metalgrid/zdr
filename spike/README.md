# zdr-spike — Phase 0 engine/IR spike

Throwaway standalone CLI proving (or disproving) the YuNet + SFace ONNX
pipeline on this machine's dual cameras. Standalone crate: its own
`[workspace]` table in `Cargo.toml` detaches it from the repo root
workspace. Nothing here touches PAM, systemd, or any existing crate.

- Detector: YuNet `face_detection_yunet_2023mar.onnx` (232,589 B, MIT)
- Recognizer: SFace `face_recognition_sface_2021dec.onnx` (38,696,353 B, Apache-2.0)
- Runtime: `ort = "=2.0.0-rc.14"` (statically linked ONNX Runtime 1.31; no
  system libonnxruntime needed)
- RGB camera: `/dev/video0`, MJPG 640x480
- IR camera: `/dev/v4l/by-path/pci-0000:00:14.0-usb-0:6:1.2-video-index0`
  (GREY 640x360 raw). 640-wide only, never 1080p.

## Build

```sh
cd spike
cargo build --release
./scripts/download-models.sh   # downloads + SHA-256-verifies models into models/ (gitignored)
```

## Run

All commands take a global `--model-dir <dir>` (default `models`).

```sh
# Paired capture from both cameras (discards 10 warm-up frames per sensor).
# Writes rgb.png + ir.png and prints mean brightness per sensor.
./target/release/zdr-spike capture --out-dir captures

# YuNet detection on one image: boxes + 5 landmarks + scores.
./target/release/zdr-spike detect --image captures/rgb.png

# Detect, align largest face to 112x112, run SFace, print embedding dim/norm.
./target/release/zdr-spike embed --image photo.jpg

# Cosine similarity between the largest faces of two images.
./target/release/zdr-spike compare --a photo1.jpg --b photo2.jpg

# Live test: capture paired frames, embed IR (gray replicated to 3ch) and RGB
# separately, print cosine scores of each against every enroll image.
./target/release/zdr-spike verify-live --enroll-dir enroll/

# Latency: per-stage mean/p95 (detect, align+embed) + peak RSS (VmHWM).
./target/release/zdr-spike bench --image captures/rgb.png --iters 50
```

## Tests

```sh
cargo test              # 8 unit tests: cosine, alignment math, YuNet decoding (no models/cameras needed)
cargo test -- --ignored # + model-gated integration tests (needs models/ downloaded;
                        #   YuNet blank-image, SFace synthetic 128-d embedding, align+embed latency)
```

---

# Owner test protocol (needs a human — please run this)

Everything below is copy-paste. Run from the `spike/` directory.
Reference score: OpenCV's SFace cosine match threshold is **0.363**
(scores above ≈ same person, below ≈ different). Report the actual
numbers, not just pass/fail.

## 1. Enroll yourself (3–5 photos, IR + RGB)

Use the spike's own capture so enrollment matches the real sensors:

```sh
cd spike
mkdir -p enroll/live1 enroll/live2 enroll/live3
./target/release/zdr-spike capture --out-dir enroll/live1   # sit centered, look at the cameras
./target/release/zdr-spike capture --out-dir enroll/live2   # slight head turn
./target/release/zdr-spike capture --out-dir enroll/live3   # different distance
```

That gives `enroll/live*/rgb.png` and `enroll/live*/ir.png`. `verify-live`
only reads images directly inside `--enroll-dir`, so flatten copies:

```sh
mkdir -p enroll/all
cp enroll/live1/rgb.png enroll/all/rgb1.png
cp enroll/live2/rgb.png enroll/all/rgb2.png
cp enroll/live3/rgb.png enroll/all/rgb3.png
cp enroll/live1/ir.png  enroll/all/ir1.png
cp enroll/live2/ir.png  enroll/all/ir2.png
cp enroll/live3/ir.png  enroll/all/ir3.png
```

(Phone/camera photos of yourself also work as enroll images — anything
with a clear frontal face. The sensor-native ones above are the most
representative.)

## 2. Verify as yourself

```sh
./target/release/zdr-spike verify-live --enroll-dir enroll/all
```

Sit in front of the cameras. **Report back:** every `rgb vs ...` and
`ir vs ...` cosine score, plus each sensor's `best:` line.

## 3. Printed-photo attack

Print a photo of yourself (or hold a printed photo up), then:

```sh
./target/release/zdr-spike verify-live --enroll-dir enroll/all
```

**Report back:** all scores. A print *should* score high on plain RGB/IR
matching alone — that's expected; the layered liveness gates come later.
What matters now is the raw number, especially the IR score.

## 4. Phone-photo attack

Display a photo of yourself on a phone, hold it to the cameras, then:

```sh
./target/release/zdr-spike verify-live --enroll-dir enroll/all
```

**Report back:** all scores. Phone screens emit almost no IR face
pattern, so the IR scores are the interesting ones.

## 5. Dark-room / IR emitter test

In a dark room (lights off, monitor dimmed if you can):

```sh
./target/release/zdr-spike capture --out-dir captures-dark
./target/release/zdr-spike verify-live --enroll-dir enroll/all
```

**Report back:**
- The `mean brightness ir:` value from the capture, compared with a
  lit-room capture. If IR brightness in darkness is still substantial,
  the IR emitter is on while streaming; if it drops to near zero, the
  emitter is off and needs a separate enable method (open Phase 0
  question).
- All verify-live scores in the dark.

## What to report back (summary)

1. Step 2: all RGB and IR cosine scores (owner, live).
2. Step 3: all scores (printed photo).
3. Step 4: all scores (phone photo).
4. Step 5: dark-room IR mean brightness vs lit-room value, and all scores.
5. Anything odd: missed detections (`no face` errors), wrong boxes, crashes.
