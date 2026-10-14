//! Template store v1 (Step 11): versioned binary embeddings, with the
//! interim `ir*.png` files kept only as a one-time import path.
//!
//! Layout: `<auth-dir>/<user>/templates.bin`
//! Format: magic `"ZDRT"`, u16 version = 1, u32 count, then per template
//! [`EMBEDDING_DIM`] little-endian f32 values. Writes are atomic (temp
//! file in the same directory + rename) and the file is mode 0600.
//!
//! Load rules: if `templates.bin` exists it is authoritative; a corrupt
//! file (wrong magic/version/dimension, truncated, trailing bytes) is
//! rejected with a clear error and the user fails closed (no templates,
//! no PNG fallback). Only when no `templates.bin` exists and `ir*.png`
//! files are present are the PNGs embedded once and `templates.bin`
//! written; the PNGs are left untouched.

use crate::engine::FaceEngine;
use crate::error::{DaemonError, Result};
use image::RgbImage;
use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};

/// SFace embedding dimension. All stored/compared templates must match.
pub const EMBEDDING_DIM: usize = 128;
pub const TEMPLATE_MAGIC: &[u8; 4] = b"ZDRT";
pub const TEMPLATE_VERSION: u16 = 1;
const HEADER_LEN: usize = 4 + 2 + 4;

pub struct TemplateStore {
    auth_dir: PathBuf,
    cache: HashMap<String, Vec<Vec<f32>>>,
}

pub fn valid_user(user: &str) -> bool {
    !user.is_empty() && user != "." && user != ".." && !user.contains(['/', '\\', '\0'])
}

pub fn templates_bin_path(auth_dir: &Path, user: &str) -> PathBuf {
    auth_dir.join(user).join("templates.bin")
}

/// Serialize embeddings. Every vector must be exactly EMBEDDING_DIM.
pub fn encode_templates(templates: &[Vec<f32>]) -> Result<Vec<u8>> {
    for t in templates {
        if t.len() != EMBEDDING_DIM {
            return Err(DaemonError::Invalid(format!(
                "template dimension {} != EMBEDDING_DIM {EMBEDDING_DIM}",
                t.len()
            )));
        }
    }
    let count = u32::try_from(templates.len())
        .map_err(|_| DaemonError::Invalid("too many templates".into()))?;
    let mut out = Vec::with_capacity(HEADER_LEN + templates.len() * EMBEDDING_DIM * 4);
    out.extend_from_slice(TEMPLATE_MAGIC);
    out.extend_from_slice(&TEMPLATE_VERSION.to_le_bytes());
    out.extend_from_slice(&count.to_le_bytes());
    for t in templates {
        for v in t {
            out.extend_from_slice(&v.to_le_bytes());
        }
    }
    Ok(out)
}

/// Parse a `templates.bin` payload, rejecting any corruption.
pub fn decode_templates(bytes: &[u8]) -> Result<Vec<Vec<f32>>> {
    if bytes.len() < HEADER_LEN {
        return Err(DaemonError::Invalid(format!(
            "templates.bin too short: {} bytes, need at least {HEADER_LEN}",
            bytes.len()
        )));
    }
    if &bytes[0..4] != TEMPLATE_MAGIC {
        return Err(DaemonError::Invalid(
            "templates.bin bad magic (expected ZDRT)".into(),
        ));
    }
    let version = u16::from_le_bytes([bytes[4], bytes[5]]);
    if version != TEMPLATE_VERSION {
        return Err(DaemonError::Invalid(format!(
            "templates.bin unsupported version {version} (expected {TEMPLATE_VERSION})"
        )));
    }
    let count = u32::from_le_bytes([bytes[6], bytes[7], bytes[8], bytes[9]]) as usize;
    let expected = HEADER_LEN
        .checked_add(
            count
                .checked_mul(EMBEDDING_DIM * 4)
                .ok_or_else(|| DaemonError::Invalid("templates.bin count overflow".into()))?,
        )
        .ok_or_else(|| DaemonError::Invalid("templates.bin size overflow".into()))?;
    if bytes.len() != expected {
        return Err(DaemonError::Invalid(format!(
            "templates.bin size mismatch: {count} templates of dimension {EMBEDDING_DIM} \
             need {expected} bytes, file has {} (wrong dimension or truncated/corrupt)",
            bytes.len()
        )));
    }
    let mut out = Vec::with_capacity(count);
    let mut off = HEADER_LEN;
    for _ in 0..count {
        let mut v = Vec::with_capacity(EMBEDDING_DIM);
        for _ in 0..EMBEDDING_DIM {
            v.push(f32::from_le_bytes([
                bytes[off],
                bytes[off + 1],
                bytes[off + 2],
                bytes[off + 3],
            ]));
            off += 4;
        }
        out.push(v);
    }
    Ok(out)
}

pub fn load_templates_file(path: &Path) -> Result<Vec<Vec<f32>>> {
    let bytes = std::fs::read(path).map_err(|e| crate::error::io_at(path, e))?;
    decode_templates(&bytes)
}

/// Atomically write `templates.bin` for `user` (temp file + rename),
/// mode 0600 on the file (and 0700 on the user dir where we create it).
pub fn write_templates_file(
    auth_dir: &Path,
    user: &str,
    templates: &[Vec<f32>],
) -> Result<PathBuf> {
    if !valid_user(user) {
        return Err(DaemonError::Invalid(format!("invalid user name {user:?}")));
    }
    let dir = auth_dir.join(user);
    std::fs::create_dir_all(&dir).map_err(|e| crate::error::io_at(&dir, e))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
    }
    let bytes = encode_templates(templates)?;
    let final_path = dir.join("templates.bin");
    // Temp file in the same directory so rename stays on one filesystem.
    let tmp_path = dir.join(format!(".templates.bin.tmp-{}", std::process::id()));
    let write_result = (|| -> Result<()> {
        let mut f =
            std::fs::File::create(&tmp_path).map_err(|e| crate::error::io_at(&tmp_path, e))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            f.set_permissions(std::fs::Permissions::from_mode(0o600))
                .map_err(|e| crate::error::io_at(&tmp_path, e))?;
        }
        f.write_all(&bytes)
            .map_err(|e| crate::error::io_at(&tmp_path, e))?;
        f.sync_all()
            .map_err(|e| crate::error::io_at(&tmp_path, e))?;
        drop(f);
        std::fs::rename(&tmp_path, &final_path).map_err(|e| crate::error::io_at(&final_path, e))?;
        Ok(())
    })();
    if write_result.is_err() {
        let _ = std::fs::remove_file(&tmp_path);
    }
    write_result?;
    // Rename preserves the temp file's mode; assert 0600 explicitly in
    // case a pre-existing file/filesystem behaved unexpectedly.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&final_path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| crate::error::io_at(&final_path, e))?;
    }
    Ok(final_path)
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

/// Embed every IR template image for `user`. Files with no detectable
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

    /// Startup pass: load templates for every user directory present.
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
    /// `templates.bin` wins; corrupt bin = fail closed; PNGs are a
    /// one-time import only when no bin exists.
    pub fn refresh(&mut self, engine: &mut dyn FaceEngine, user: &str) -> usize {
        if !valid_user(user) {
            self.cache.insert(user.to_string(), Vec::new());
            return 0;
        }
        let bin = templates_bin_path(&self.auth_dir, user);
        if bin.is_file() {
            return match load_templates_file(&bin) {
                Ok(embs) => {
                    let count = embs.len();
                    eprintln!("zdrd: templates user={user} count={count} (templates.bin)");
                    self.cache.insert(user.to_string(), embs);
                    count
                }
                Err(e) => {
                    eprintln!(
                        "zdrd: templates user={user}: rejecting {}: {e} (fail closed, no templates)",
                        bin.display()
                    );
                    self.cache.insert(user.to_string(), Vec::new());
                    0
                }
            };
        }
        if !template_files(&self.auth_dir, user).is_empty() {
            let embs = embed_templates(engine, &self.auth_dir, user);
            if !embs.is_empty() {
                match write_templates_file(&self.auth_dir, user, &embs) {
                    Ok(p) => eprintln!(
                        "zdrd: templates user={user}: imported {} PNG template(s) -> {}",
                        embs.len(),
                        p.display()
                    ),
                    Err(e) => {
                        eprintln!("zdrd: templates user={user}: PNG import write failed: {e}")
                    }
                }
            }
            let count = embs.len();
            eprintln!("zdrd: templates user={user} count={count} (imported ir*.png)");
            self.cache.insert(user.to_string(), embs);
            return count;
        }
        self.cache.insert(user.to_string(), Vec::new());
        0
    }

    /// Persist `templates` for `user` to templates.bin and reload the
    /// in-memory cache from what was written. Returns stored count.
    pub fn store(&mut self, user: &str, templates: &[Vec<f32>]) -> Result<usize> {
        write_templates_file(&self.auth_dir, user, templates)?;
        // Reload from disk so the cache provably matches the file.
        let embs = load_templates_file(&templates_bin_path(&self.auth_dir, user))?;
        let count = embs.len();
        self.cache.insert(user.to_string(), embs);
        Ok(count)
    }

    pub fn get(&self, user: &str) -> &[Vec<f32>] {
        self.cache.get(user).map(Vec::as_slice).unwrap_or(&[])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn emb(v: f32) -> Vec<f32> {
        vec![v; EMBEDDING_DIM]
    }

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "zdrd-templates-test-{}-{}",
            std::process::id(),
            tag
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    #[test]
    fn store_round_trip() {
        let dir = temp_dir("roundtrip");
        let templates = vec![emb(0.5), emb(-0.25)];
        let path = write_templates_file(&dir, "alice", &templates).expect("write");
        assert_eq!(load_templates_file(&path).expect("load"), templates);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).expect("meta").permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "templates.bin must be 0600");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn corruption_rejected() {
        let good = encode_templates(&[emb(1.0)]).expect("encode");
        // Wrong magic.
        let mut bad = good.clone();
        bad[0] = b'X';
        assert!(decode_templates(&bad).is_err());
        // Wrong version.
        let mut bad = good.clone();
        bad[4] = 99;
        assert!(decode_templates(&bad).is_err());
        // Truncated (also covers wrong-dimension payloads, whose size
        // cannot match count * EMBEDDING_DIM * 4).
        assert!(decode_templates(&good[..good.len() - 4]).is_err());
        // Trailing garbage.
        let mut bad = good.clone();
        bad.extend_from_slice(&[0u8; 4]);
        assert!(decode_templates(&bad).is_err());
        // Empty / short header.
        assert!(decode_templates(&[]).is_err());
        assert!(decode_templates(b"ZDRT").is_err());
        // Encode rejects wrong dimension.
        assert!(encode_templates(&[vec![0.0; 3]]).is_err());
    }

    #[test]
    fn corrupt_bin_fails_closed_without_png_fallback() {
        let dir = temp_dir("corrupt");
        let user_dir = dir.join("alice");
        std::fs::create_dir_all(&user_dir).expect("user dir");
        std::fs::write(user_dir.join("templates.bin"), b"not a template file").expect("write");
        let mut store = TemplateStore::new(dir.clone());
        let mut engine = NoFaceEngine;
        assert_eq!(store.refresh(&mut engine, "alice"), 0);
        assert!(store.get("alice").is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    struct NoFaceEngine;
    impl FaceEngine for NoFaceEngine {
        fn detect(&mut self, _img: &RgbImage) -> Result<Vec<crate::yunet::Face>> {
            Ok(Vec::new())
        }
        fn embed_face(
            &mut self,
            _img: &RgbImage,
            _face: &crate::yunet::Face,
        ) -> Result<crate::engine::Embedding> {
            Err(DaemonError::NoFace("none".into()))
        }
    }
}
