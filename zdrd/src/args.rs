use clap::Parser;
use std::path::PathBuf;

/// Daemon CLI. Every setting is optional on the command line:
/// precedence is CLI flag > `/etc/zdr/zdrd.toml` > built-in default
/// (see `config.rs`). No camera path is hard-coded any more; cameras
/// default to auto-detection.
#[derive(Parser, Debug, Clone)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    /// Path to the daemon config file.
    #[arg(long, default_value = crate::config::DEFAULT_CONFIG_PATH)]
    pub config: PathBuf,

    /// Path to the YuNet face-detection ONNX model.
    #[arg(long)]
    pub yunet: Option<PathBuf>,

    /// Path to the SFace face-recognition ONNX model.
    #[arg(long)]
    pub sface: Option<PathBuf>,

    /// RGB camera device, or `auto` to auto-detect.
    #[arg(long)]
    pub rgb_camera: Option<String>,

    /// IR camera device, or `auto` to auto-detect.
    #[arg(long)]
    pub ir_camera: Option<String>,

    /// Directory holding per-user templates: <auth-dir>/<user>/templates.bin
    #[arg(long)]
    pub auth_dir: Option<PathBuf>,

    /// Cosine-similarity match threshold.
    #[arg(long)]
    pub threshold: Option<f32>,

    /// Require the IR camera (default true). `--require-ir=false`
    /// selects insecure RGB-only mode; see the README warning.
    #[arg(long, num_args = 0..=1, default_missing_value = "true", value_parser = clap::value_parser!(bool))]
    pub require_ir: Option<bool>,
}
