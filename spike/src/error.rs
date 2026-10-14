use std::fmt;
use std::path::PathBuf;

/// Typed errors for the spike. No `unwrap()` on I/O or model paths.
#[derive(Debug)]
pub enum SpikeError {
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

impl fmt::Display for SpikeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SpikeError::Io { path, source } => {
                write!(f, "I/O error on {}: {source}", path.display())
            }
            SpikeError::IoMsg(m) => write!(f, "I/O error: {m}"),
            SpikeError::Image(e) => write!(f, "image error: {e}"),
            SpikeError::Ort(e) => write!(f, "ONNX Runtime error: {e}"),
            SpikeError::V4l(e) => write!(f, "camera (V4L2) error: {e}"),
            SpikeError::Model(m) => write!(f, "model error: {m}"),
            SpikeError::NoFace(m) => write!(f, "no face: {m}"),
            SpikeError::Invalid(m) => write!(f, "invalid input: {m}"),
        }
    }
}

impl std::error::Error for SpikeError {}

impl From<std::io::Error> for SpikeError {
    fn from(source: std::io::Error) -> Self {
        SpikeError::IoMsg(source.to_string())
    }
}
impl From<image::ImageError> for SpikeError {
    fn from(e: image::ImageError) -> Self {
        SpikeError::Image(e)
    }
}
impl From<ort::error::Error> for SpikeError {
    fn from(e: ort::error::Error) -> Self {
        SpikeError::Ort(e)
    }
}

pub type Result<T> = std::result::Result<T, SpikeError>;

pub fn io_at(path: &std::path::Path, source: std::io::Error) -> SpikeError {
    SpikeError::Io {
        path: path.to_path_buf(),
        source,
    }
}
