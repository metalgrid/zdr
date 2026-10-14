//! Interim per-user IR templates (Step 5 proper replaces this with
//! embedding-only storage; this interim form is image files on disk).
//!
//! Layout: `<auth-dir>/<user>/ir*.png`. At daemon startup and again on
//! every CaptureVerify the files are loaded, each is embedded via the
//! engine, and the embeddings are cached per user. Unknown users and
//! users with zero usable IR templates yield an empty set, which the
//! verify path treats as fail-closed `nomatch`.

use crate::engine::FaceEngine;
use crate::error::Result;
use image::RgbImage;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

pub struct TemplateStore {
    auth_dir: PathBuf,
    cache: HashMap<String, Vec<Vec<f32>>>,
}

fn valid_user(user: &str) -> bool {
    !user.is_empty() && user != "." && user != ".." && !user.contains(['/', '\\', '\0'])
}

/// IR template files for `user`, sorted for deterministic embedding order.
pub fn template_files(auth_dir: &Path, user: &str) -> Vec<PathBuf> {
    if !valid_user(user) {
        return Vec::new();
    }
    let dir = auth_dir.join(user);
    let mut files: Vec<PathBuf> = match std::fs::read_dir(&dir) {
        Ok(rd) => rd
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .map(|n| {
                        let n = n.to_ascii_lowercase();
                        n.starts_with("ir") && n.ends_with(".png")
                    })
                    .unwrap_or(false)
            })
            .collect(),
        Err(_) => Vec::new(),
    };
    files.sort();
    files
}

/// Embed every IR template image for `user`. Images are grayscale IR
/// frames replicated to RGB (as in the spike). Files with no detectable
/// face are skipped with a log line.
pub fn embed_templates(engine: &mut dyn FaceEngine, auth_dir: &Path, user: &str) -> Vec<Vec<f32>> {
    let mut out = Vec::new();
    for path in template_files(auth_dir, user) {
        match load_and_embed(engine, &path) {
            Ok(Some(emb)) => out.push(emb),
            Ok(None) => eprintln!("zdrd: template {}: no face, skipped", path.display()),
            Err(e) => eprintln!("zdrd: template {}: skipped ({e})", path.display()),
        }
    }
    out
}

fn load_and_embed(engine: &mut dyn FaceEngine, path: &Path) -> Result<Option<Vec<f32>>> {
    // Template files are grayscale IR frames; replicate to RGB exactly as
    // live IR frames are handled in verify.
    // PNG grayscale decodes to equal RGB channels, matching gray_to_rgb.
    let rgb: RgbImage = crate::capture::load_image_rgb(path)?;
    match engine.embed_largest(&rgb) {
        Ok((_, emb)) => Ok(Some(emb.vector)),
        Err(crate::error::DaemonError::NoFace(_)) => Ok(None),
        Err(e) => Err(e),
    }
}

impl TemplateStore {
    pub fn new(auth_dir: PathBuf) -> Self {
        TemplateStore {
            auth_dir,
            cache: HashMap::new(),
        }
    }

    /// Startup pass: embed templates for every user directory present.
    pub fn load_all(&mut self, engine: &mut dyn FaceEngine) {
        let users: Vec<String> = match std::fs::read_dir(&self.auth_dir) {
            Ok(rd) => rd
                .filter_map(|e| e.ok())
                .filter(|e| e.path().is_dir())
                .filter_map(|e| e.file_name().into_string().ok())
                .collect(),
            Err(e) => {
                eprintln!(
                    "zdrd: cannot read auth-dir {}: {e} (templates will load on demand)",
                    self.auth_dir.display()
                );
                return;
            }
        };
        for user in users {
            self.refresh(engine, &user);
        }
    }

    /// (Re)load and cache one user's embeddings; returns the count.
    pub fn refresh(&mut self, engine: &mut dyn FaceEngine, user: &str) -> usize {
        let embs = embed_templates(engine, &self.auth_dir, user);
        let count = embs.len();
        eprintln!("zdrd: templates user={user} count={count} (interim ir*.png)");
        self.cache.insert(user.to_string(), embs);
        count
    }

    pub fn get(&self, user: &str) -> &[Vec<f32>] {
        self.cache.get(user).map(Vec::as_slice).unwrap_or(&[])
    }
}
