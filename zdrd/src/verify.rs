//! Capture-verify: the only place a camera is ever opened, reached only
//! from CaptureVerify after an approved consent request has been consumed.

use crate::align;
use crate::capture::{self, gray_to_rgb};
use crate::engine::{FaceEngine, OnnxEngine};
use crate::error::DaemonError;
use crate::service::Verifier;
use crate::templates::TemplateStore;
use image::{GrayImage, RgbImage};
use std::path::PathBuf;
use std::sync::Mutex;

/// Owns the engine + template cache behind one mutex: ONNX sessions and
/// V4L2 captures are both blocking, single-threaded work.
pub struct FaceVerifier {
    inner: Mutex<FaceInner>,
}

struct FaceInner {
    engine: Box<dyn FaceEngine>,
    templates: TemplateStore,
    rgb_camera: String,
    ir_camera: String,
    threshold: f32,
}

impl FaceVerifier {
    pub fn new(
        engine: OnnxEngine,
        auth_dir: PathBuf,
        rgb_camera: String,
        ir_camera: String,
        threshold: f32,
    ) -> FaceVerifier {
        FaceVerifier::with_engine(Box::new(engine), auth_dir, rgb_camera, ir_camera, threshold)
    }

    pub fn with_engine(
        mut engine: Box<dyn FaceEngine>,
        auth_dir: PathBuf,
        rgb_camera: String,
        ir_camera: String,
        threshold: f32,
    ) -> FaceVerifier {
        let mut templates = TemplateStore::new(auth_dir);
        templates.load_all(engine.as_mut());
        FaceVerifier {
            inner: Mutex::new(FaceInner {
                engine,
                templates,
                rgb_camera,
                ir_camera,
                threshold,
            }),
        }
    }
}

impl Verifier for FaceVerifier {
    fn verify(&self, user: &str) -> (bool, String) {
        let mut guard = match self.inner.lock() {
            Ok(g) => g,
            Err(_) => return (false, "engine".to_string()),
        };
        // Reborrow through a plain &mut so disjoint field borrows work.
        let inner: &mut FaceInner = &mut guard;
        // Reload this user's interim templates on every CaptureVerify.
        // Split the two field borrows: refresh borrows templates mutably
        // and the engine mutably at the same time.
        let (templates, engine) = (&mut inner.templates, &mut inner.engine);
        templates.refresh(engine.as_mut(), user);
        if inner.templates.get(user).is_empty() {
            // Unknown user or zero IR templates: fail closed, no capture.
            return (false, "nomatch".to_string());
        }
        let paired = match capture::capture_paired(&inner.rgb_camera, &inner.ir_camera) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("zdrd: capture failed for user={user}: {e}");
                return (false, "camera".to_string());
            }
        };
        let templates: Vec<Vec<f32>> = inner.templates.get(user).to_vec();
        let threshold = inner.threshold;
        verify_images(
            inner.engine.as_mut(),
            &templates,
            &paired.rgb,
            &paired.ir,
            threshold,
        )
    }
}

/// Verify core over already-captured frames (mock-engine testable):
/// face required in IR first, then in RGB (cross-sensor presence gate),
/// then the IR face is embedded and compared to the user's IR templates.
pub fn verify_images(
    engine: &mut dyn FaceEngine,
    templates: &[Vec<f32>],
    rgb: &RgbImage,
    ir: &GrayImage,
    threshold: f32,
) -> (bool, String) {
    if templates.is_empty() {
        return (false, "nomatch".to_string());
    }
    let ir_rgb = gray_to_rgb(ir);
    let ir_face = match engine.detect(&ir_rgb) {
        Ok(mut faces) if !faces.is_empty() => {
            faces.sort_by(|a, b| {
                b.area()
                    .partial_cmp(&a.area())
                    .unwrap_or(std::cmp::Ordering::Equal)
            });
            faces.remove(0)
        }
        Ok(_) => return (false, "noface-ir".to_string()),
        Err(e) => {
            eprintln!("zdrd: IR detection failed: {e}");
            return (false, "engine".to_string());
        }
    };
    match engine.detect(rgb) {
        Ok(faces) if !faces.is_empty() => {}
        Ok(_) => return (false, "noface-rgb".to_string()),
        Err(e) => {
            eprintln!("zdrd: RGB detection failed: {e}");
            return (false, "engine".to_string());
        }
    }
    let emb = match engine.embed_face(&ir_rgb, &ir_face) {
        Ok(e) => e,
        Err(DaemonError::NoFace(_)) => return (false, "noface-ir".to_string()),
        Err(e) => {
            eprintln!("zdrd: IR embedding failed: {e}");
            return (false, "engine".to_string());
        }
    };
    let best = templates
        .iter()
        .map(|t| align::cosine(&emb.vector, t))
        .fold(f32::MIN, f32::max);
    eprintln!("zdrd: verify best cosine={best:.4} threshold={threshold}");
    if best >= threshold {
        (true, "match".to_string())
    } else {
        (false, "nomatch".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::Embedding;
    use crate::error::Result;
    use crate::yunet::Face;

    /// Mock engine: the 1x1 test image has no face; anything else does.
    struct MockEngine {
        embedding: Vec<f32>,
    }

    fn face() -> Face {
        Face {
            x: 0.0,
            y: 0.0,
            w: 10.0,
            h: 10.0,
            landmarks: [[0.0; 2]; 5],
            score: 0.9,
        }
    }

    impl FaceEngine for MockEngine {
        fn detect(&mut self, img: &RgbImage) -> Result<Vec<Face>> {
            if img.width() == 1 {
                return Ok(Vec::new());
            }
            Ok(vec![face()])
        }
        fn embed_face(&mut self, _img: &RgbImage, _face: &Face) -> Result<Embedding> {
            Ok(Embedding {
                vector: self.embedding.clone(),
                raw_norm: 1.0,
            })
        }
    }

    fn img(w: u32) -> RgbImage {
        RgbImage::new(w, w)
    }
    fn gray(w: u32) -> GrayImage {
        GrayImage::new(w, w)
    }

    #[test]
    fn match_above_threshold() {
        let mut eng = MockEngine {
            embedding: vec![1.0, 0.0],
        };
        let (m, r) = verify_images(&mut eng, &[vec![1.0, 0.0]], &img(4), &gray(4), 0.363);
        assert!(m && r == "match");
    }

    #[test]
    fn nomatch_below_threshold_and_empty_templates() {
        let mut eng = MockEngine {
            embedding: vec![0.0, 1.0],
        };
        let (m, r) = verify_images(&mut eng, &[vec![1.0, 0.0]], &img(4), &gray(4), 0.363);
        assert!(!m && r == "nomatch");
        let (m, r) = verify_images(&mut eng, &[], &img(4), &gray(4), 0.363);
        assert!(!m && r == "nomatch");
    }

    #[test]
    fn noface_gates() {
        let mut eng = MockEngine {
            embedding: vec![1.0],
        };
        let (m, r) = verify_images(&mut eng, &[vec![1.0]], &img(4), &gray(1), 0.363);
        assert!(!m && r == "noface-ir");
        let (m, r) = verify_images(&mut eng, &[vec![1.0]], &img(1), &gray(4), 0.363);
        assert!(!m && r == "noface-rgb");
    }
}
