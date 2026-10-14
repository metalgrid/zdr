//! Paired camera capture via V4L2 (ported from the Phase 0 spike).
//!
//! - RGB: MJPG 640x480.
//! - IR: GREY 640x360 raw.
//! Device paths are supplied by the caller (stable /dev/v4l/by-path defaults in args).
//!
//! GREY is headerless Luma8: copy row by row using the format stride.
//! At least 10 warm-up frames are discarded per sensor so auto-exposure
//! can settle. Never capture above 640 wide.

use crate::error::{DaemonError, Result};
use image::{GrayImage, RgbImage};
use std::path::Path;
use v4l::buffer::Type;
use v4l::io::mmap::Stream as MmapStream;
use v4l::io::traits::CaptureStream;
use v4l::video::Capture;
use v4l::{Device, FourCC};

pub const WARMUP_FRAMES: usize = 10;

pub struct PairedCapture {
    pub rgb: RgbImage,
    pub ir: GrayImage,
}

/// Capture one frame from `path` after discarding `warmup` frames.
/// Returns (raw buffer, negotiated format).
fn grab_frame(
    path: &str,
    fourcc: &[u8; 4],
    width: u32,
    height: u32,
    warmup: usize,
) -> Result<(Vec<u8>, v4l::Format)> {
    let dev = Device::with_path(path).map_err(DaemonError::V4l)?;
    let mut fmt = dev.format().map_err(DaemonError::V4l)?;
    fmt.width = width;
    fmt.height = height;
    fmt.fourcc = FourCC::new(fourcc);
    let fmt = dev.set_format(&fmt).map_err(DaemonError::V4l)?;
    if fmt.width != width || fmt.height != height {
        return Err(DaemonError::Invalid(format!(
            "{path}: driver gave {}x{} instead of {width}x{height}",
            fmt.width, fmt.height
        )));
    }
    let mut stream =
        MmapStream::with_buffers(&dev, Type::VideoCapture, 4).map_err(DaemonError::V4l)?;
    let mut last: Vec<u8> = Vec::new();
    for _ in 0..=warmup {
        let (buf, _meta) = stream.next().map_err(DaemonError::V4l)?;
        last = buf.to_vec();
    }
    Ok((last, fmt))
}

pub fn capture_rgb(path: &str) -> Result<RgbImage> {
    let (buf, _fmt) = grab_frame(path, b"MJPG", 640, 480, WARMUP_FRAMES)?;
    let img = image::load_from_memory(&buf)?;
    Ok(img.to_rgb8())
}

pub fn capture_ir(path: &str) -> Result<GrayImage> {
    let (buf, fmt) = grab_frame(path, b"GREY", 640, 360, WARMUP_FRAMES)?;
    let (w, h) = (fmt.width as usize, fmt.height as usize);
    let stride = fmt.stride as usize;
    if stride < w || buf.len() < stride * (h - 1) + w {
        return Err(DaemonError::Invalid(format!(
            "IR frame too small: {} bytes, stride {stride}, {w}x{h}",
            buf.len()
        )));
    }
    let mut pixels = vec![0u8; w * h];
    for y in 0..h {
        let row = &buf[y * stride..y * stride + w];
        pixels[y * w..(y + 1) * w].copy_from_slice(row);
    }
    GrayImage::from_vec(fmt.width, fmt.height, pixels)
        .ok_or_else(|| DaemonError::Invalid("IR pixel buffer size mismatch".into()))
}

pub fn capture_paired(rgb_path: &str, ir_path: &str) -> Result<PairedCapture> {
    let rgb = capture_rgb(rgb_path)?;
    let ir = capture_ir(ir_path)?;
    Ok(PairedCapture { rgb, ir })
}

/// Replicate a grayscale image into 3 RGB channels (for SFace on IR).
pub fn gray_to_rgb(img: &GrayImage) -> RgbImage {
    RgbImage::from_fn(img.width(), img.height(), |x, y| {
        let v = img.get_pixel(x, y)[0];
        image::Rgb([v, v, v])
    })
}

pub fn load_image_rgb(path: &Path) -> Result<RgbImage> {
    // Sniff the real format from the bytes, not the file extension.
    let bytes = std::fs::read(path).map_err(|e| crate::error::io_at(path, e))?;
    let img = image::load_from_memory(&bytes)?;
    Ok(img.to_rgb8())
}
