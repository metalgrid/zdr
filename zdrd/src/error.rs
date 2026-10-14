use std::fmt;
use std::path::PathBuf;

/// Typed errors for the daemon. No `unwrap()` on I/O or model paths.
#[derive(Debug)]
pub enum DaemonError {
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    IoMsg(String),
    Image(image::ImageError),
    Ort(ort::error::Error),
    V4l(std::io::Error),
    Model(String),
    NoFace(String),
    Invalid(String),
}

impl fmt::Display for DaemonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DaemonError::Io { path, source } => {
                write!(f, "I/O error on {}: {source}", path.display())
            }
            DaemonError::IoMsg(m) => write!(f, "I/O error: {m}"),
            DaemonError::Image(e) => write!(f, "image error: {e}"),
            DaemonError::Ort(e) => write!(f, "ONNX Runtime error: {e}"),
            DaemonError::V4l(e) => write!(f, "camera (V4L2) error: {e}"),
            DaemonError::Model(m) => write!(f, "model error: {m}"),
            DaemonError::NoFace(m) => write!(f, "no face: {m}"),
            DaemonError::Invalid(m) => write!(f, "invalid input: {m}"),
        }
    }
}

impl std::error::Error for DaemonError {}

impl From<std::io::Error> for DaemonError {
    fn from(source: std::io::Error) -> Self {
        DaemonError::IoMsg(source.to_string())
    }
}
impl From<image::ImageError> for DaemonError {
    fn from(e: image::ImageError) -> Self {
        DaemonError::Image(e)
    }
}
impl From<ort::error::Error> for DaemonError {
    fn from(e: ort::error::Error) -> Self {
        DaemonError::Ort(e)
    }
}

pub type Result<T> = std::result::Result<T, DaemonError>;

pub fn io_at(path: &std::path::Path, source: std::io::Error) -> DaemonError {
    DaemonError::Io {
        path: path.to_path_buf(),
        source,
    }
}
