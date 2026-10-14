//! Enrollment state machine (Step 11). Bus-independent like
//! `consent.rs`: callers inject the time and session id, and captures
//! go through the `FaceEngine` trait, so every gate is unit-testable
//! without D-Bus, cameras, or models.
//!
//! Invariants:
//! - One live session per user; a second `begin` is `Busy`.
//! - Sessions expire after 120 s (`DEFAULT_TTL`).
//! - A capture is stored only if it passes every quality gate:
//!   exactly one face in IR and in RGB, IR mean brightness in
//!   [20, 230], and cosine < 0.995 against every already-captured
//!   session embedding (duplicate-pose rejection).
//! - Five good captures make the session `ready` for `FinishEnroll`.

use crate::align;
use crate::capture::gray_to_rgb;
use crate::engine::FaceEngine;
use crate::error::DaemonError;
use crate::feedback::FeedbackKind;
use image::{GrayImage, RgbImage};
use std::collections::HashMap;
use std::time::{Duration, Instant};

pub const DEFAULT_TTL: Duration = Duration::from_secs(120);
pub const NEEDED: usize = 5;
pub const MIN_BRIGHTNESS: f32 = 20.0;
pub const MAX_BRIGHTNESS: f32 = 230.0;
pub const DUPLICATE_COSINE: f32 = 0.995;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnrollState {
    Captured,
    Rejected,
    Ready,
}

impl EnrollState {
    pub fn as_str(&self) -> &'static str {
        match self {
            EnrollState::Captured => "captured",
            EnrollState::Rejected => "rejected",
            EnrollState::Ready => "ready",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnrollError {
    /// A live session already exists for this user.
    Busy,
    /// No session with this id (unknown, cancelled, finished).
    Unknown,
    /// The session passed its expiry (and has been removed).
    Expired,
    /// Finish attempted before `NEEDED` captures.
    NotReady,
}

impl std::fmt::Display for EnrollError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            EnrollError::Busy => "an enrollment session is already active for this user",
            EnrollError::Unknown => "unknown enrollment session",
            EnrollError::Expired => "enrollment session expired",
            EnrollError::NotReady => "enrollment is not ready (fewer than 5 captures)",
        };
        f.write_str(s)
    }
}

impl std::error::Error for EnrollError {}

#[derive(Debug, Clone, PartialEq)]
pub struct CaptureAttempt {
    pub state: EnrollState,
    pub captured: usize,
    pub needed: usize,
    pub kind: FeedbackKind,
}

#[derive(Debug, Clone)]
struct Session {
    user: String,
    embeddings: Vec<Vec<f32>>,
    expires_at: Instant,
}

pub struct Enrollments {
    sessions: HashMap<String, Session>,
    by_user: HashMap<String, String>,
    ttl: Duration,
}

impl Default for Enrollments {
    fn default() -> Self {
        Self::new()
    }
}

impl Enrollments {
    pub fn new() -> Self {
        Self::with_ttl(DEFAULT_TTL)
    }

    pub fn with_ttl(ttl: Duration) -> Self {
        Enrollments {
            sessions: HashMap::new(),
            by_user: HashMap::new(),
            ttl,
        }
    }

    pub fn begin(&mut self, enroll_id: &str, user: &str, now: Instant) -> Result<(), EnrollError> {
        self.sweep_user(user, now);
        if self.by_user.contains_key(user) {
            return Err(EnrollError::Busy);
        }
        self.sessions.insert(
            enroll_id.to_string(),
            Session {
                user: user.to_string(),
                embeddings: Vec::new(),
                expires_at: now + self.ttl,
            },
        );
        self.by_user.insert(user.to_string(), enroll_id.to_string());
        Ok(())
    }

    fn sweep_user(&mut self, user: &str, now: Instant) {
        let Some(id) = self.by_user.get(user).cloned() else {
            return;
        };
        let expired = match self.sessions.get(&id) {
            Some(s) => now >= s.expires_at,
            None => true,
        };
        if expired {
            self.remove(&id);
        }
    }

    /// Live session or the reason it cannot be used. Expired sessions
    /// are removed as a side effect.
    fn live(&mut self, enroll_id: &str, now: Instant) -> Result<&Session, EnrollError> {
        let expired = match self.sessions.get(enroll_id) {
            None => return Err(EnrollError::Unknown),
            Some(s) => now >= s.expires_at,
        };
        if expired {
            self.remove(enroll_id);
            return Err(EnrollError::Expired);
        }
        self.sessions.get(enroll_id).ok_or(EnrollError::Unknown)
    }

    pub fn user_for(&mut self, enroll_id: &str, now: Instant) -> Result<String, EnrollError> {
        Ok(self.live(enroll_id, now)?.user.clone())
    }

    pub fn embeddings_for(
        &mut self,
        enroll_id: &str,
        now: Instant,
    ) -> Result<Vec<Vec<f32>>, EnrollError> {
        Ok(self.live(enroll_id, now)?.embeddings.clone())
    }

    pub fn captured_for(&mut self, enroll_id: &str, now: Instant) -> Result<usize, EnrollError> {
        Ok(self.live(enroll_id, now)?.embeddings.len())
    }

    /// Apply one evaluated capture: store `embedding` when present
    /// (its kind is then `stored`), otherwise count it as rejected.
    pub fn apply_capture(
        &mut self,
        enroll_id: &str,
        now: Instant,
        kind: FeedbackKind,
        embedding: Option<Vec<f32>>,
    ) -> Result<CaptureAttempt, EnrollError> {
        // Validate liveness first (removes expired sessions).
        let _ = self.live(enroll_id, now)?;
        let session = self
            .sessions
            .get_mut(enroll_id)
            .ok_or(EnrollError::Unknown)?;
        let (state, kind) = match embedding {
            Some(emb) => {
                session.embeddings.push(emb);
                if session.embeddings.len() >= NEEDED {
                    (EnrollState::Ready, FeedbackKind::Stored)
                } else {
                    (EnrollState::Captured, FeedbackKind::Stored)
                }
            }
            None => (EnrollState::Rejected, kind),
        };
        Ok(CaptureAttempt {
            state,
            captured: session.embeddings.len(),
            needed: NEEDED,
            kind,
        })
    }

    /// Capture from already-grabbed frames through the quality gates.
    /// The live D-Bus path splits snapshot/capture/apply across a
    /// worker thread; this fused form drives the state machine in tests.
    #[cfg(test)]
    pub fn capture(
        &mut self,
        enroll_id: &str,
        now: Instant,
        engine: &mut dyn FaceEngine,
        rgb: &RgbImage,
        ir: &GrayImage,
    ) -> Result<CaptureAttempt, EnrollError> {
        let existing = self.embeddings_for(enroll_id, now)?;
        let (kind, emb) = evaluate_capture(engine, rgb, ir, &existing);
        self.apply_capture(enroll_id, now, kind, emb)
    }

    /// Snapshot a ready session for finishing without consuming it;
    /// the caller removes it once the store write succeeds.
    pub fn ready_snapshot(
        &mut self,
        enroll_id: &str,
        now: Instant,
    ) -> Result<(String, Vec<Vec<f32>>), EnrollError> {
        let s = self.live(enroll_id, now)?;
        if s.embeddings.len() < NEEDED {
            return Err(EnrollError::NotReady);
        }
        Ok((s.user.clone(), s.embeddings.clone()))
    }

    pub fn cancel(&mut self, enroll_id: &str) -> bool {
        self.remove(enroll_id)
    }

    fn remove(&mut self, enroll_id: &str) -> bool {
        match self.sessions.remove(enroll_id) {
            Some(s) => {
                if self.by_user.get(&s.user).map(String::as_str) == Some(enroll_id) {
                    self.by_user.remove(&s.user);
                }
                true
            }
            None => false,
        }
    }
}

/// Quality gates for one paired capture. On success returns
/// (`stored`, Some(IR embedding)); on rejection the gate's kind and
/// `None`. Gate order: face counts (IR then RGB), IR brightness,
/// duplicate pose.
pub fn evaluate_capture(
    engine: &mut dyn FaceEngine,
    rgb: &RgbImage,
    ir: &GrayImage,
    existing: &[Vec<f32>],
) -> (FeedbackKind, Option<Vec<f32>>) {
    let ir_rgb = gray_to_rgb(ir);
    let ir_faces = match engine.detect(&ir_rgb) {
        Ok(f) => f,
        Err(_) => return (FeedbackKind::Error, None),
    };
    if ir_faces.is_empty() {
        return (FeedbackKind::NoFace, None);
    }
    if ir_faces.len() > 1 {
        return (FeedbackKind::MultipleFaces, None);
    }
    let rgb_faces = match engine.detect(rgb) {
        Ok(f) => f,
        Err(_) => return (FeedbackKind::Error, None),
    };
    if rgb_faces.is_empty() {
        return (FeedbackKind::NoFace, None);
    }
    if rgb_faces.len() > 1 {
        return (FeedbackKind::MultipleFaces, None);
    }
    let brightness = mean_brightness(ir);
    if brightness < MIN_BRIGHTNESS {
        return (FeedbackKind::TooDark, None);
    }
    if brightness > MAX_BRIGHTNESS {
        return (FeedbackKind::TooBright, None);
    }
    let emb = match engine.embed_face(&ir_rgb, &ir_faces[0]) {
        Ok(e) => e,
        Err(DaemonError::NoFace(_)) => return (FeedbackKind::NoFace, None),
        Err(_) => return (FeedbackKind::Error, None),
    };
    if existing
        .iter()
        .any(|t| align::cosine(&emb.vector, t) >= DUPLICATE_COSINE)
    {
        return (FeedbackKind::DuplicatePose, None);
    }
    (FeedbackKind::Stored, Some(emb.vector))
}

/// RGB-only quality gates (Step 14, `require_ir = false`): exactly
/// one RGB face, RGB luma brightness in [20, 230], duplicate-pose
/// rejection. On success returns (`stored`, Some(RGB embedding)).
pub fn evaluate_capture_rgb(
    engine: &mut dyn FaceEngine,
    rgb: &RgbImage,
    existing: &[Vec<f32>],
) -> (FeedbackKind, Option<Vec<f32>>) {
    let rgb_faces = match engine.detect(rgb) {
        Ok(f) => f,
        Err(_) => return (FeedbackKind::Error, None),
    };
    if rgb_faces.is_empty() {
        return (FeedbackKind::NoFace, None);
    }
    if rgb_faces.len() > 1 {
        return (FeedbackKind::MultipleFaces, None);
    }
    let brightness = mean_rgb_brightness(rgb);
    if brightness < MIN_BRIGHTNESS {
        return (FeedbackKind::TooDark, None);
    }
    if brightness > MAX_BRIGHTNESS {
        return (FeedbackKind::TooBright, None);
    }
    let emb = match engine.embed_face(rgb, &rgb_faces[0]) {
        Ok(e) => e,
        Err(DaemonError::NoFace(_)) => return (FeedbackKind::NoFace, None),
        Err(_) => return (FeedbackKind::Error, None),
    };
    if existing
        .iter()
        .any(|t| align::cosine(&emb.vector, t) >= DUPLICATE_COSINE)
    {
        return (FeedbackKind::DuplicatePose, None);
    }
    (FeedbackKind::Stored, Some(emb.vector))
}

/// Mean luma of an RGB frame (0..=255, Rec. 601 weights).
pub fn mean_rgb_brightness(rgb: &RgbImage) -> f32 {
    if rgb.is_empty() {
        return 0.0;
    }
    let sum: f64 = rgb
        .pixels()
        .map(|p| 0.299 * p[0] as f64 + 0.587 * p[1] as f64 + 0.114 * p[2] as f64)
        .sum();
    (sum / (rgb.width() as f64 * rgb.height() as f64)) as f32
}

/// Mean pixel value of an IR frame (0..=255).
pub fn mean_brightness(ir: &GrayImage) -> f32 {
    if ir.is_empty() {
        return 0.0;
    }
    let sum: u64 = ir.pixels().map(|p| p[0] as u64).sum();
    sum as f32 / (ir.width() as f32 * ir.height() as f32)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::Embedding;
    use crate::error::Result;
    use crate::yunet::Face;
    use std::collections::VecDeque;

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

    /// Mock engine: each `detect` pops the next face-count from
    /// `detect_queue` (evaluate calls IR first, then RGB); each
    /// `embed_face` pops the next embedding.
    struct MockEngine {
        detect_queue: VecDeque<usize>,
        embeddings: VecDeque<Vec<f32>>,
    }

    impl MockEngine {
        fn new(detects: &[usize], embeddings: Vec<Vec<f32>>) -> Self {
            MockEngine {
                detect_queue: detects.iter().copied().collect(),
                embeddings: embeddings.into_iter().collect(),
            }
        }
        fn good(embedding: Vec<f32>) -> Self {
            Self::new(&[1, 1], vec![embedding])
        }
    }

    impl FaceEngine for MockEngine {
        fn detect(&mut self, _img: &RgbImage) -> Result<Vec<Face>> {
            let n = self.detect_queue.pop_front().unwrap_or(1);
            Ok((0..n).map(|_| face()).collect())
        }
        fn embed_face(&mut self, _img: &RgbImage, _face: &Face) -> Result<Embedding> {
            let vector = self
                .embeddings
                .pop_front()
                .unwrap_or_else(|| vec![1.0, 0.0]);
            Ok(Embedding {
                vector,
                raw_norm: 1.0,
            })
        }
    }

    fn rgb() -> RgbImage {
        RgbImage::new(4, 4)
    }

    fn ir(brightness: u8) -> GrayImage {
        GrayImage::from_fn(4, 4, |_, _| image::Luma([brightness]))
    }

    fn setup() -> (Enrollments, Instant) {
        let mut e = Enrollments::new();
        let now = Instant::now();
        e.begin("enr1", "alice", now).expect("begin");
        (e, now)
    }

    #[test]
    fn good_capture_stores_and_counts() {
        let (mut e, now) = setup();
        let mut eng = MockEngine::good(vec![1.0, 0.0]);
        let a = e
            .capture("enr1", now, &mut eng, &rgb(), &ir(128))
            .expect("capture");
        assert_eq!(a.state, EnrollState::Captured);
        assert_eq!((a.captured, a.needed), (1, NEEDED));
        assert_eq!(a.kind, FeedbackKind::Stored);
    }

    #[test]
    fn face_count_gates() {
        let (mut e, now) = setup();
        for (detects, want) in [
            (vec![0, 1], FeedbackKind::NoFace),        // IR: none
            (vec![2, 1], FeedbackKind::MultipleFaces), // IR: two
            (vec![1, 0], FeedbackKind::NoFace),        // RGB: none
            (vec![1, 2], FeedbackKind::MultipleFaces), // RGB: two
        ] {
            let mut eng = MockEngine::new(&detects, vec![vec![1.0, 0.0]]);
            let a = e
                .capture("enr1", now, &mut eng, &rgb(), &ir(128))
                .expect("capture");
            assert_eq!(a.state, EnrollState::Rejected, "{detects:?}");
            assert_eq!(a.kind, want, "{detects:?}");
            assert_eq!(a.captured, 0, "rejections never store");
        }
    }

    #[test]
    fn brightness_gates() {
        let (mut e, now) = setup();
        let mut eng = MockEngine::good(vec![1.0, 0.0]);
        let a = e
            .capture("enr1", now, &mut eng, &rgb(), &ir(10))
            .expect("dark");
        assert_eq!(a.kind, FeedbackKind::TooDark);
        let mut eng = MockEngine::good(vec![1.0, 0.0]);
        let a = e
            .capture("enr1", now, &mut eng, &rgb(), &ir(250))
            .expect("bright");
        assert_eq!(a.kind, FeedbackKind::TooBright);
        // Boundary values pass.
        for level in [20u8, 230] {
            let mut eng = MockEngine::good(vec![1.0, 0.0]);
            let a = e
                .capture("enr1", now, &mut eng, &rgb(), &ir(level))
                .expect("boundary");
            assert_eq!(a.kind, FeedbackKind::Stored, "level {level}");
            e.cancel("enr1");
            e.begin("enr1", "alice", now).expect("re-begin");
        }
    }

    #[test]
    fn duplicate_pose_rejected() {
        let (mut e, now) = setup();
        let mut eng = MockEngine::good(vec![1.0, 0.0]);
        e.capture("enr1", now, &mut eng, &rgb(), &ir(128))
            .expect("first");
        // Identical embedding: cosine 1.0 >= 0.995.
        let mut eng = MockEngine::good(vec![1.0, 0.0]);
        let a = e
            .capture("enr1", now, &mut eng, &rgb(), &ir(128))
            .expect("dup");
        assert_eq!(a.state, EnrollState::Rejected);
        assert_eq!(a.kind, FeedbackKind::DuplicatePose);
        assert_eq!(a.captured, 1);
        // Orthogonal embedding is a new pose and stores.
        let mut eng = MockEngine::good(vec![0.0, 1.0]);
        let a = e
            .capture("enr1", now, &mut eng, &rgb(), &ir(128))
            .expect("new pose");
        assert_eq!(a.state, EnrollState::Captured);
        assert_eq!(a.captured, 2);
    }

    #[test]
    fn rgb_only_capture_gates() {
        // Brightness comes from the RGB frame itself.
        let bright_rgb = RgbImage::from_fn(4, 4, |_, _| image::Rgb([128, 128, 128]));
        let dark_rgb = RgbImage::from_fn(4, 4, |_, _| image::Rgb([5, 5, 5]));
        let mut eng = MockEngine::good(vec![1.0, 0.0]);
        let (kind, emb) = evaluate_capture_rgb(&mut eng, &bright_rgb, &[]);
        assert_eq!(kind, FeedbackKind::Stored);
        assert_eq!(emb, Some(vec![1.0, 0.0]));
        let mut eng = MockEngine::good(vec![1.0, 0.0]);
        assert_eq!(
            evaluate_capture_rgb(&mut eng, &dark_rgb, &[]).0,
            FeedbackKind::TooDark
        );
        let mut eng = MockEngine::new(&[0], vec![vec![1.0, 0.0]]);
        assert_eq!(
            evaluate_capture_rgb(&mut eng, &bright_rgb, &[]).0,
            FeedbackKind::NoFace
        );
        let mut eng = MockEngine::new(&[2], vec![vec![1.0, 0.0]]);
        assert_eq!(
            evaluate_capture_rgb(&mut eng, &bright_rgb, &[]).0,
            FeedbackKind::MultipleFaces
        );
        let mut eng = MockEngine::good(vec![1.0, 0.0]);
        assert_eq!(
            evaluate_capture_rgb(&mut eng, &bright_rgb, &[vec![1.0, 0.0]]).0,
            FeedbackKind::DuplicatePose
        );
    }

    #[test]
    fn five_captures_ready_then_finish_snapshot() {
        let (mut e, now) = setup();
        assert_eq!(e.ready_snapshot("enr1", now), Err(EnrollError::NotReady));
        // Five mutually orthogonal-ish embeddings (pairwise cosine 0).
        let bases: Vec<Vec<f32>> = (0..NEEDED)
            .map(|i| {
                let mut v = vec![0.0; NEEDED];
                v[i] = 1.0;
                v
            })
            .collect();
        for (i, emb) in bases.iter().enumerate() {
            let mut eng = MockEngine::good(emb.clone());
            let a = e
                .capture("enr1", now, &mut eng, &rgb(), &ir(128))
                .expect("capture");
            if i + 1 < NEEDED {
                assert_eq!(a.state, EnrollState::Captured);
            } else {
                assert_eq!(a.state, EnrollState::Ready);
                assert_eq!(a.captured, NEEDED);
            }
        }
        let (user, embs) = e.ready_snapshot("enr1", now).expect("ready");
        assert_eq!(user, "alice");
        assert_eq!(embs, bases);
    }

    #[test]
    fn one_session_per_user_and_expiry() {
        let (mut e, now) = setup();
        assert_eq!(e.begin("enr2", "alice", now), Err(EnrollError::Busy));
        assert!(e.begin("enr2", "bob", now).is_ok());
        // After the 120 s TTL the session is expired and frees the user.
        let later = now + Duration::from_secs(121);
        assert_eq!(e.captured_for("enr1", later), Err(EnrollError::Expired));
        assert!(e.begin("enr3", "alice", later).is_ok());
        assert_eq!(e.captured_for("nope", later), Err(EnrollError::Unknown));
    }

    #[test]
    fn finish_writes_store_in_temp_dir() {
        // State machine -> template store integration (temp dir, no bus).
        let dir = std::env::temp_dir().join(format!("zdrd-enroll-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        let (mut e, now) = setup();
        // Session embeddings must be EMBEDDING_DIM long to be storable.
        let bases: Vec<Vec<f32>> = (0..NEEDED)
            .map(|i| {
                let mut v = vec![0.0; crate::templates::EMBEDDING_DIM];
                v[i] = 1.0;
                v
            })
            .collect();
        for emb in &bases {
            let mut eng = MockEngine::good(emb.clone());
            e.capture("enr1", now, &mut eng, &rgb(), &ir(128))
                .expect("capture");
        }
        let (user, embs) = e.ready_snapshot("enr1", now).expect("ready");
        let mut store = crate::templates::TemplateStore::new(dir.clone());
        let stored = store
            .store(&user, &embs, crate::templates::TemplateMode::Ir)
            .expect("store");
        assert_eq!(stored, NEEDED);
        assert!(e.cancel("enr1"), "session consumed after finish");
        // Reloaded from disk by a fresh store view of the same file.
        let loaded = crate::templates::load_templates_file(&crate::templates::templates_bin_path(
            &dir, "alice",
        ))
        .expect("load");
        assert_eq!(loaded, bases);
        assert_eq!(store.get("alice").len(), NEEDED);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
