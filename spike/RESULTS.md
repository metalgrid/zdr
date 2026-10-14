# Phase 0 spike — measured results (2026-10-14)

Machine: this workstation (20 cores, 32 GB RAM), Rust 1.99, release build
unless noted. No human face was present during these runs — the owner
tests in README.md are still outstanding.

## Build

- `cargo build` / `cargo build --release`: **OK**. `ort = "=2.0.0-rc.14"`
  downloaded and statically linked ONNX Runtime 1.31 with no system
  libonnxruntime and no libc++ link failure. No packages installed, no sudo.
- `cargo clippy`: clean. `cargo fmt --check`: clean after `cargo fmt`.
- API note: in rc.14 `Session::builder` requires an `ort::environment::Environment`
  (`ort::init().build()`); the engine keeps it alive for the sessions' lifetime.
- Model quirk found: the YuNet 2023mar ONNX export has a **fixed 640x640
  input**. The engine letterboxes (aspect preserved, zero pad bottom/right,
  never upscales) into 640x640 and maps boxes/landmarks back to original
  image coordinates.

## Models (via scripts/download-models.sh, SHA-256 pinned in the script)

| File | Size | SHA-256 |
|---|---|---|
| face_detection_yunet_2023mar.onnx | 232,589 B | `8f2383e4dd3cfbb4553ea8718107fc0423210dc964f9f4280604804ed2552fa4` |
| face_recognition_sface_2021dec.onnx | 38,696,353 B | `0ba9fbfa01b5270c96627c4ef784da859931e02f04419c829e83484087c34e79` |

Sizes match the expected values exactly. Models are gitignored, never committed.

## Tests

- `cargo test`: **8 unit tests pass** (cosine similarity, L2 normalize,
  similarity-transform recovery, identity warp, YuNet decode/NMS/threshold).
  No models or cameras required.
- `cargo test -- --ignored` (model-gated): **3 pass** —
  YuNet on a blank 640x480 image returns 0 faces; SFace on a synthetic
  112x112 crop returns a 128-d embedding with unit norm after
  normalization (raw norm > 0); align+embed timing test (below).

## Capture (room, no person)

`zdr-spike capture --out-dir captures` works on both sensors
(10 warm-up frames discarded per sensor):

- Final run: RGB 640x480 mean brightness **151.16/255**; IR 640x360 mean
  brightness **54.04/255**. Across repeated runs RGB ranged ~137–151 and
  IR ~54–86 (auto-exposure + changing room light), so treat single
  brightness values as indicative, not stable.

## Detection on room frames

- `detect --image captures/rgb.png` → `faces: 0`
- `detect --image captures/ir.png` → `faces: 0`
- `embed` / `compare` on room frames → clean typed `no face` error, exit 1.

Zero faces is the expected, correct result for an empty room. Not faked.

## Bench

Release build, 50 iterations, room frames (both sessions loaded):

| Run | detect mean | detect p95 | align+embed | Peak RSS (VmHWM) |
|---|---|---|---|---|
| captures/rgb.png (640x480) | 4.30 ms | 5.44 ms | n/a (no face) | 107,972 kB (105.4 MiB) |
| captures/ir.png (640x360) | 4.31 ms | 5.17 ms | n/a (no face) | 108,192 kB (105.7 MiB) |

Align+embed latency on a real face could not be benched without a face.
Synthetic substitute (release, ignored test, perfect reference landmarks
on a 320x320 synthetic image, warp + SFace): **mean 7.68 ms** over 50
iterations (13.10 ms in a debug build). Peak RSS above is for
detect-only execution with both models loaded; RSS during embed was not
separately measured.

Indicative total pipeline estimate: ~12 ms + capture time per attempt —
far below the 500 ms target. RSS ~106 MiB is below the 150 MiB target
but not by a huge margin; ONNX Runtime dominates it.

## What is proven

- ort 2.0.0-rc.14 static linking works on this machine; both models load.
- YuNet inference runs end-to-end on RGB and IR frames (640x640 letterbox).
- SFace inference runs and yields unit-normalized 128-d embeddings.
- Paired V4L2 capture works: RGB MJPG 640x480 + IR GREY 640x360 by-path,
  with warm-up frames and stride-correct grayscale decoding.
- YuNet decoding, alignment (similarity transform + bilinear warp), and
  cosine scoring are unit-tested against OpenCV's documented math.

## Owner live results (2026-10-14, recorded by the team lead)

Three verify-live runs against six enrolled templates (3 RGB + 3 IR).
SFace reference threshold: 0.363.

Run 1 — owner, live:
- IR vs IR templates: 0.9570 / 0.9678 / 0.9588. RGB vs RGB: 0.8385-0.9463.
- Cross-modal scores also pass (IR vs RGB 0.66-0.77), but the design uses IR vs IR.

Runs 2 and 3 — printed-photo and phone-photo attacks (order not labelled):
- IR: no face detected in either run. The IR gate rejects both at detection.
- RGB alone would have passed both attacks (best 0.7188 and 0.8512).
  This confirms RGB-only auth is unsafe and the IR requirement is load-bearing.

Gate verdict: PASS. YuNet+SFace with IR-primary matching is the engine.
Live IR margin: minimum 0.957 against a 0.363 threshold.
Open items stay open: dark-room emitter test, second-person separation.

## What remains unproven (needs the owner — see README.md protocol)

1. **Detection on a real face**: box/landmark accuracy on RGB and IR.
2. **IR-to-IR matching (D7 gate)**: whether SFace embeddings of IR frames
   match the same person reliably. This is the central Phase 0 question.
3. **RGB matching** of the owner vs enroll photos.
4. **Attack separation**: printed-photo and phone-photo cosine scores vs
   the owner's live scores (raw matching only; liveness gates are later).
5. **Dark-room behaviour / IR emitter**: whether the emitter is on while
   streaming (dark-room IR brightness test), and dark-room match scores.
6. **Real-face align+embed bench on this CLI** (`bench` align+embed stage
   with an actual detected face) and peak RSS during embed.
7. Cross-person separation (needs a second person).
8. SCRFD-500M + MobileFaceNet comparison pipeline from the plan was not
   built; only YuNet+SFace was spiked in this step.
