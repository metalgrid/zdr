//! Model-gated integration tests. Ignored by default: they need the ONNX
//! files from scripts/download-models.sh. Run with:
//!   cargo test -- --ignored
use std::path::Path;
use zdr_spike::align;
use zdr_spike::engine::Engine;

#[test]
#[ignore = "needs downloaded models in spike/models/"]
fn yunet_runs_and_finds_no_face_in_blank_image() {
    let mut eng = Engine::load(Path::new("models")).expect("load models");
    let img = image::RgbImage::from_pixel(640, 480, image::Rgb([30, 30, 30]));
    let faces = eng.detect(&img).expect("detect");
    assert!(
        faces.is_empty(),
        "blank image must yield no faces, got {faces:?}"
    );
}

#[test]
#[ignore = "needs downloaded models in spike/models/"]
fn align_embed_latency_on_synthetic_crop() {
    // Times the align+embed stage (warp to 112x112 + SFace) on a synthetic
    // crop. Proves latency only; recognition quality needs a real face.
    let mut eng = Engine::load(Path::new("models")).expect("load models");
    let img = image::RgbImage::from_fn(320, 320, |x, y| {
        image::Rgb([(x % 256) as u8, (y % 256) as u8, ((x + y) % 256) as u8])
    });
    let face = zdr_spike::yunet::Face {
        x: 50.0,
        y: 50.0,
        w: 200.0,
        h: 200.0,
        landmarks: align::REFERENCE.map(|p| [p[0] * 2.0 + 40.0, p[1] * 2.0 + 30.0]),
        score: 1.0,
    };
    let _ = eng.embed_face(&img, &face).expect("warm-up embed");
    let n = 50;
    let start = std::time::Instant::now();
    for _ in 0..n {
        let _ = eng.embed_face(&img, &face).expect("embed");
    }
    let mean_ms = start.elapsed().as_secs_f64() * 1000.0 / n as f64;
    println!("align+embed synthetic: mean {mean_ms:.2} ms over {n} iters");
    assert!(mean_ms < 500.0);
}

#[test]
#[ignore = "needs downloaded models in spike/models/"]
fn sface_produces_unit_128d_embedding_on_synthetic_crop() {
    let mut eng = Engine::load(Path::new("models")).expect("load models");
    // Deterministic non-trivial pattern; not a face, but proves the SFace
    // graph runs and its output shape/normalization are as expected.
    let img = image::RgbImage::from_fn(112, 112, |x, y| {
        image::Rgb([(x * 2) as u8, (y * 2) as u8, ((x + y) % 256) as u8])
    });
    let emb = eng.embed_aligned(&img).expect("embed");
    assert_eq!(emb.vector.len(), 128);
    assert!(emb.raw_norm > 0.0);
    let norm = emb
        .vector
        .iter()
        .map(|v| (*v as f64).powi(2))
        .sum::<f64>()
        .sqrt();
    assert!((norm - 1.0).abs() < 1e-5, "normalized norm = {norm}");
    let _ = align::cosine(&emb.vector, &emb.vector);
}
