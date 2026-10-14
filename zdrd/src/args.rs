use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug, Clone)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    /// Path to the YuNet face-detection ONNX model.
    #[arg(long)]
    pub yunet: PathBuf,

    /// Path to the SFace face-recognition ONNX model.
    #[arg(long)]
    pub sface: PathBuf,

    /// RGB camera device.
    #[arg(
        long,
        default_value = "/dev/v4l/by-path/pci-0000:00:14.0-usb-0:6:1.0-video-index0"
    )]
    pub rgb_camera: String,

    /// IR camera device.
    #[arg(
        long,
        default_value = "/dev/v4l/by-path/pci-0000:00:14.0-usb-0:6:1.2-video-index0"
    )]
    pub ir_camera: String,

    /// Directory holding per-user interim templates: <auth-dir>/<user>/ir*.png
    #[arg(long, default_value = "/var/lib/zdr")]
    pub auth_dir: PathBuf,

    /// Cosine-similarity match threshold for IR templates.
    #[arg(long, default_value_t = 0.363)]
    pub threshold: f32,
}
