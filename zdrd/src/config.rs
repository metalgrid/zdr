//! Daemon config file (Step 14): `/etc/zdr/zdrd.toml`.
//!
//! Precedence for every key: CLI flag > config file > built-in
//! default. A missing config file is fine (all defaults); a present
//! but unreadable/invalid file is a fatal startup error — silently
//! ignoring a broken config could silently weaken authentication.

use crate::args::Args;
use crate::camfind::DetectedCameras;
use crate::error::{DaemonError, Result};
use serde::Deserialize;
use std::path::{Path, PathBuf};

pub const DEFAULT_CONFIG_PATH: &str = "/etc/zdr/zdrd.toml";
pub const DEFAULT_YUNET: &str = "/usr/share/zdr/models/face_detection_yunet_2023mar.onnx";
pub const DEFAULT_SFACE: &str = "/usr/share/zdr/models/face_recognition_sface_2021dec.onnx";
pub const DEFAULT_AUTH_DIR: &str = "/var/lib/zdr";
pub const DEFAULT_THRESHOLD: f32 = 0.363;
pub const DEFAULT_REQUIRE_IR: bool = true;

/// Parsed `/etc/zdr/zdrd.toml`. Every key is optional; `None` means
/// "not set in the file". Unknown keys are rejected so typos fail
/// loudly at startup instead of being silently ignored.
#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct FileConfig {
    pub rgb_camera: Option<String>,
    pub ir_camera: Option<String>,
    pub require_ir: Option<bool>,
    pub threshold: Option<f32>,
    pub auth_dir: Option<PathBuf>,
    pub yunet: Option<PathBuf>,
    pub sface: Option<PathBuf>,
}

/// Load the config file. Missing file => `Ok(None)`; present but
/// invalid => fatal `Err`.
pub fn load_file(path: &Path) -> Result<Option<FileConfig>> {
    if !path.exists() {
        return Ok(None);
    }
    let text = std::fs::read_to_string(path).map_err(|e| crate::error::io_at(path, e))?;
    let parsed: FileConfig = toml::from_str(&text).map_err(|e| {
        DaemonError::Invalid(format!(
            "invalid config file {}: {e} (refusing to start)",
            path.display()
        ))
    })?;
    Ok(Some(parsed))
}

fn is_auto(spec: Option<&str>) -> bool {
    match spec {
        None => true,
        Some(s) => s.eq_ignore_ascii_case("auto"),
    }
}

/// Fully resolved daemon configuration after CLI > file > default
/// precedence and camera auto-detection.
#[derive(Debug, Clone, PartialEq)]
pub struct ResolvedConfig {
    pub rgb_camera: Option<PathBuf>,
    pub ir_camera: Option<PathBuf>,
    pub require_ir: bool,
    pub threshold: f32,
    pub auth_dir: PathBuf,
    pub yunet: PathBuf,
    pub sface: PathBuf,
}

/// The camera spec before detection: `Some(path)` for an explicit
/// device, `None` for auto-detect (`'auto'` or absent at both levels).
fn camera_spec(cli: Option<&str>, file: Option<&str>) -> Option<String> {
    let spec = cli.or(file);
    if is_auto(spec) {
        None
    } else {
        spec.map(str::to_string)
    }
}

impl ResolvedConfig {
    pub fn resolve(args: &Args, file: &FileConfig, detected: &DetectedCameras) -> ResolvedConfig {
        let rgb_camera = match camera_spec(args.rgb_camera.as_deref(), file.rgb_camera.as_deref()) {
            Some(p) => Some(PathBuf::from(p)),
            None => detected.rgb.clone(),
        };
        let ir_camera = match camera_spec(args.ir_camera.as_deref(), file.ir_camera.as_deref()) {
            Some(p) => Some(PathBuf::from(p)),
            None => detected.ir.clone(),
        };
        ResolvedConfig {
            rgb_camera,
            ir_camera,
            require_ir: args
                .require_ir
                .or(file.require_ir)
                .unwrap_or(DEFAULT_REQUIRE_IR),
            threshold: args
                .threshold
                .or(file.threshold)
                .unwrap_or(DEFAULT_THRESHOLD),
            auth_dir: args
                .auth_dir
                .clone()
                .or_else(|| file.auth_dir.clone())
                .unwrap_or_else(|| PathBuf::from(DEFAULT_AUTH_DIR)),
            yunet: args
                .yunet
                .clone()
                .or_else(|| file.yunet.clone())
                .unwrap_or_else(|| PathBuf::from(DEFAULT_YUNET)),
            sface: args
                .sface
                .clone()
                .or_else(|| file.sface.clone())
                .unwrap_or_else(|| PathBuf::from(DEFAULT_SFACE)),
        }
    }

    /// Whether any camera still needs auto-detection. `main` uses
    /// this to scan devices only when a camera is actually `'auto'`.
    pub fn needs_detection(args: &Args, file: &FileConfig) -> bool {
        camera_spec(args.rgb_camera.as_deref(), file.rgb_camera.as_deref()).is_none()
            || camera_spec(args.ir_camera.as_deref(), file.ir_camera.as_deref()).is_none()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::camfind::DetectedCameras;

    fn args() -> Args {
        Args {
            config: PathBuf::from(DEFAULT_CONFIG_PATH),
            yunet: None,
            sface: None,
            rgb_camera: None,
            ir_camera: None,
            auth_dir: None,
            threshold: None,
            require_ir: None,
        }
    }

    fn detected() -> DetectedCameras {
        DetectedCameras {
            rgb: Some(PathBuf::from("/dev/v4l/by-path/detected-rgb")),
            ir: Some(PathBuf::from("/dev/v4l/by-path/detected-ir")),
            summary: Vec::new(),
        }
    }

    #[test]
    fn defaults_when_nothing_set() {
        let r = ResolvedConfig::resolve(&args(), &FileConfig::default(), &detected());
        assert_eq!(r.rgb_camera, detected().rgb);
        assert_eq!(r.ir_camera, detected().ir);
        assert!(r.require_ir);
        assert_eq!(r.threshold, DEFAULT_THRESHOLD);
        assert_eq!(r.auth_dir, PathBuf::from(DEFAULT_AUTH_DIR));
        assert_eq!(r.yunet, PathBuf::from(DEFAULT_YUNET));
        assert_eq!(r.sface, PathBuf::from(DEFAULT_SFACE));
    }

    #[test]
    fn file_beats_default_and_cli_beats_file() {
        let file: FileConfig = toml::from_str(
            "threshold = 0.5\nauth_dir = \"/tmp/from-file\"\nrgb_camera = \"/dev/file-rgb\"\nrequire_ir = false\n",
        )
        .expect("parse file config");
        let r = ResolvedConfig::resolve(&args(), &file, &detected());
        assert_eq!(r.threshold, 0.5);
        assert_eq!(r.auth_dir, PathBuf::from("/tmp/from-file"));
        assert_eq!(r.rgb_camera, Some(PathBuf::from("/dev/file-rgb")));
        assert!(!r.require_ir);

        let mut cli = args();
        cli.threshold = Some(0.9);
        cli.auth_dir = Some(PathBuf::from("/tmp/from-cli"));
        cli.rgb_camera = Some("/dev/cli-rgb".to_string());
        cli.require_ir = Some(true);
        let r = ResolvedConfig::resolve(&cli, &file, &detected());
        assert_eq!(r.threshold, 0.9);
        assert_eq!(r.auth_dir, PathBuf::from("/tmp/from-cli"));
        assert_eq!(r.rgb_camera, Some(PathBuf::from("/dev/cli-rgb")));
        assert!(r.require_ir);
    }

    #[test]
    fn auto_spec_uses_detection_and_explicit_skips_it() {
        let mut cli = args();
        cli.rgb_camera = Some("auto".to_string());
        let r = ResolvedConfig::resolve(&cli, &FileConfig::default(), &detected());
        assert_eq!(r.rgb_camera, detected().rgb);
        assert!(ResolvedConfig::needs_detection(
            &cli,
            &FileConfig::default()
        ));

        cli.rgb_camera = Some("/dev/explicit-rgb".to_string());
        cli.ir_camera = Some("/dev/explicit-ir".to_string());
        assert!(!ResolvedConfig::needs_detection(
            &cli,
            &FileConfig::default()
        ));
    }

    #[test]
    fn missing_file_ok_invalid_file_fatal() {
        let dir = std::env::temp_dir().join(format!("zdrd-config-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        assert_eq!(
            load_file(&dir.join("absent.toml")).expect("missing ok"),
            None
        );

        let bad = dir.join("bad.toml");
        std::fs::write(&bad, "threshold = \"not a float\"\n").expect("write bad");
        assert!(load_file(&bad).is_err(), "invalid config must be fatal");
        let unknown = dir.join("unknown.toml");
        std::fs::write(&unknown, "nope = 1\n").expect("write unknown");
        assert!(load_file(&unknown).is_err(), "unknown keys must be fatal");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
