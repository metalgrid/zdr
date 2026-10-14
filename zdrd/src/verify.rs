//! Capture-verify: the only place a camera is ever opened, reached only
//! from CaptureVerify after an approved consent request has been consumed.

use crate::align;
use crate::capture::{self, gray_to_rgb};
use crate::engine::{FaceEngine, OnnxEngine};
use crate::error::DaemonError;
use crate::feedback::FeedbackKind;
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
    rgb_camera: Option<String>,
    ir_camera: Option<String>,
    threshold: f32,
    require_ir: bool,
}

/// The sensor mode this daemon captures/matches with.
fn capture_mode(require_ir: bool) -> crate::templates::TemplateMode {
    if require_ir {
        crate::templates::TemplateMode::Ir
    } else {
        crate::templates::TemplateMode::Rgb
    }
}

/// True when stored templates exist in a different mode than the
/// daemon captures: cross-mode matching is always refused.
pub fn mode_mismatch(
    stored: Option<crate::templates::TemplateMode>,
    daemon: crate::templates::TemplateMode,
) -> bool {
    matches!(stored, Some(m) if m != daemon)
}

impl FaceVerifier {
    pub fn new(
        engine: OnnxEngine,
        auth_dir: PathBuf,
        rgb_camera: Option<PathBuf>,
        ir_camera: Option<PathBuf>,
        threshold: f32,
        require_ir: bool,
    ) -> FaceVerifier {
        FaceVerifier::with_engine(
            Box::new(engine),
            auth_dir,
            rgb_camera,
            ir_camera,
            threshold,
            require_ir,
        )
    }

    pub fn with_engine(
        mut engine: Box<dyn FaceEngine>,
        auth_dir: PathBuf,
        rgb_camera: Option<PathBuf>,
        ir_camera: Option<PathBuf>,
        threshold: f32,
        require_ir: bool,
    ) -> FaceVerifier {
        let mut templates = TemplateStore::new(auth_dir);
        templates.load_all(engine.as_mut());
        let to_str = |p: Option<PathBuf>| p.map(|p| p.display().to_string());
        FaceVerifier {
            inner: Mutex::new(FaceInner {
                engine,
                templates,
                rgb_camera: to_str(rgb_camera),
                ir_camera: to_str(ir_camera),
                threshold,
                require_ir,
            }),
        }
    }

    pub fn require_ir(&self) -> bool {
        match self.inner.lock() {
            Ok(g) => g.require_ir,
            Err(_) => true,
        }
    }
}

impl Verifier for FaceVerifier {
    fn require_ir(&self) -> bool {
        FaceVerifier::require_ir(self)
    }

    fn capture_for_enroll(&self, existing: &[Vec<f32>]) -> (FeedbackKind, Option<Vec<f32>>) {
        let mut guard = match self.inner.lock() {
            Ok(g) => g,
            Err(_) => return (FeedbackKind::Error, None),
        };
        let inner: &mut FaceInner = &mut guard;
        if inner.require_ir {
            let (rgb_path, ir_path) = match (&inner.rgb_camera, &inner.ir_camera) {
                (Some(r), Some(i)) => (r.clone(), i.clone()),
                _ => return (FeedbackKind::Error, None),
            };
            let paired = match capture::capture_paired(&rgb_path, &ir_path) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("zdrd: enroll capture failed: {e}");
                    return (FeedbackKind::Error, None);
                }
            };
            crate::enroll::evaluate_capture(
                inner.engine.as_mut(),
                &paired.rgb,
                &paired.ir,
                existing,
            )
        } else {
            let rgb_path = match &inner.rgb_camera {
                Some(r) => r.clone(),
                None => return (FeedbackKind::Error, None),
            };
            let rgb = match capture::capture_rgb(&rgb_path) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("zdrd: enroll RGB capture failed: {e}");
                    return (FeedbackKind::Error, None);
                }
            };
            crate::enroll::evaluate_capture_rgb(inner.engine.as_mut(), &rgb, existing)
        }
    }

    fn finish_enroll_store(&self, user: &str, embeddings: &[Vec<f32>]) -> Result<usize, String> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| "verifier state poisoned".to_string())?;
        let mode = capture_mode(guard.require_ir);
        guard
            .templates
            .store(user, embeddings, mode)
            .map_err(|e| e.to_string())
    }

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
            // Unknown user or zero templates: fail closed, no capture.
            return (false, "nomatch".to_string());
        }
        let daemon_mode = capture_mode(inner.require_ir);
        if mode_mismatch(inner.templates.mode(user), daemon_mode) {
            eprintln!(
                "zdrd: verify user={user}: stored template mode {} != daemon capture mode {} (refusing cross-mode matching)",
                inner
                    .templates
                    .mode(user)
                    .map(|m| m.as_str())
                    .unwrap_or("?"),
                daemon_mode.as_str()
            );
            return (false, "nomatch".to_string());
        }
        let templates: Vec<Vec<f32>> = inner.templates.get(user).to_vec();
        let threshold = inner.threshold;
        if inner.require_ir {
            let (rgb_path, ir_path) = match (&inner.rgb_camera, &inner.ir_camera) {
                (Some(r), Some(i)) => (r.clone(), i.clone()),
                _ => return (false, "camera".to_string()),
            };
            let paired = match capture::capture_paired(&rgb_path, &ir_path) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("zdrd: capture failed for user={user}: {e}");
                    return (false, "camera".to_string());
                }
            };
            verify_images(
                inner.engine.as_mut(),
                &templates,
                &paired.rgb,
                &paired.ir,
                threshold,
            )
        } else {
            let rgb_path = match &inner.rgb_camera {
                Some(r) => r.clone(),
                None => return (false, "camera".to_string()),
            };
            let rgb = match capture::capture_rgb(&rgb_path) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("zdrd: RGB capture failed for user={user}: {e}");
                    return (false, "camera".to_string());
                }
            };
            verify_rgb_image(inner.engine.as_mut(), &templates, &rgb, threshold)
        }
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
    eprintln!(
        "zdrd: verify best cosine={best:.4} threshold={threshold} raw_norm={:.3}",
        emb.raw_norm
    );
    if best >= threshold {
        (true, "match".to_string())
    } else {
        (false, "nomatch".to_string())
    }
}

/// RGB-only verify core (Step 14): exactly the RGB path of the paired
/// flow — a face must be present in RGB, its embedding is compared
/// to the user's RGB templates.
pub fn verify_rgb_image(
    engine: &mut dyn FaceEngine,
    templates: &[Vec<f32>],
    rgb: &RgbImage,
    threshold: f32,
) -> (bool, String) {
    if templates.is_empty() {
        return (false, "nomatch".to_string());
    }
    let face = match engine.detect(rgb) {
        Ok(mut faces) if !faces.is_empty() => {
            faces.sort_by(|a, b| {
                b.area()
                    .partial_cmp(&a.area())
                    .unwrap_or(std::cmp::Ordering::Equal)
            });
            faces.remove(0)
        }
        Ok(_) => return (false, "noface-rgb".to_string()),
        Err(e) => {
            eprintln!("zdrd: RGB detection failed: {e}");
            return (false, "engine".to_string());
        }
    };
    let emb = match engine.embed_face(rgb, &face) {
        Ok(e) => e,
        Err(DaemonError::NoFace(_)) => return (false, "noface-rgb".to_string()),
        Err(e) => {
            eprintln!("zdrd: RGB embedding failed: {e}");
            return (false, "engine".to_string());
        }
    };
    let best = templates
        .iter()
        .map(|t| align::cosine(&emb.vector, t))
        .fold(f32::MIN, f32::max);
    eprintln!(
        "zdrd: verify (RGB) best cosine={best:.4} threshold={threshold} raw_norm={:.3}",
        emb.raw_norm
    );
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
    fn rgb_verify_match_nomatch_noface() {
        let mut eng = MockEngine {
            embedding: vec![1.0, 0.0],
        };
        let (m, r) = verify_rgb_image(&mut eng, &[vec![1.0, 0.0]], &img(4), 0.363);
        assert!(m && r == "match");
        let (m, r) = verify_rgb_image(&mut eng, &[vec![0.0, 1.0]], &img(4), 0.363);
        assert!(!m && r == "nomatch");
        let (m, r) = verify_rgb_image(&mut eng, &[vec![1.0, 0.0]], &img(1), 0.363);
        assert!(!m && r == "noface-rgb");
    }

    #[test]
    fn cross_mode_templates_refused() {
        use crate::templates::{TemplateMode, TemplateStore};
        // Unit seam: the predicate itself.
        assert!(mode_mismatch(Some(TemplateMode::Rgb), TemplateMode::Ir));
        assert!(mode_mismatch(Some(TemplateMode::Ir), TemplateMode::Rgb));
        assert!(!mode_mismatch(Some(TemplateMode::Ir), TemplateMode::Ir));
        assert!(!mode_mismatch(None, TemplateMode::Ir));

        // State-level: an IR-mode daemon with RGB templates on disk
        // refuses with nomatch *before* any camera is opened (both
        // camera paths are None here, so a capture attempt would
        // return "camera" instead).
        let dir =
            std::env::temp_dir().join(format!("zdrd-verify-mode-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        let embs = vec![vec![1.0; crate::templates::EMBEDDING_DIM]];
        let mut store = TemplateStore::new(dir.clone());
        store
            .store("alice", &embs, TemplateMode::Rgb)
            .expect("store rgb templates");
        let eng = MockEngine {
            embedding: vec![1.0, 0.0],
        };
        let verifier =
            FaceVerifier::with_engine(Box::new(eng), dir.clone(), None, None, 0.363, true);
        assert_eq!(verifier.verify("alice"), (false, "nomatch".to_string()));
        // And the mirror image: RGB daemon, IR templates.
        let mut store = TemplateStore::new(dir.clone());
        store
            .store("alice", &embs, TemplateMode::Ir)
            .expect("store ir templates");
        let eng = MockEngine {
            embedding: vec![1.0, 0.0],
        };
        let verifier =
            FaceVerifier::with_engine(Box::new(eng), dir.clone(), None, None, 0.363, false);
        assert_eq!(verifier.verify("alice"), (false, "nomatch".to_string()));
        let _ = std::fs::remove_dir_all(&dir);
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
