//! Paired camera capture via V4L2.
//!
//! - RGB: `/dev/video0`, MJPG 640x480.
//! - IR: `/dev/v4l/by-path/pci-0000:00:14.0-usb-0:6:1.2-video-index0`
//!   (stable path; resolves to /dev/video2 here), GREY 640x360 raw.
//!
//! GREY is headerless Luma8: copy row by row using the format stride.
//! At least 10 warm-up frames are discarded per sensor so auto-exposure
//! can settle. Never capture above 640 wide.

use crate::error::{Result, SpikeError};
use image::{GrayImage, RgbImage};
use std::path::Path;
use v4l::buffer::Type;
use v4l::io::mmap::Stream as MmapStream;
use v4l::io::traits::CaptureStream;
use v4l::video::Capture;
use v4l::{Device, FourCC};

pub const RGB_PATH: &str = "/dev/video0";
pub const IR_PATH: &str = "/dev/v4l/by-path/pci-0000:00:14.0-usb-0:6:1.2-video-index0";
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
    let dev = Device::with_path(path).map_err(SpikeError::V4l)?;
    let mut fmt = dev.format().map_err(SpikeError::V4l)?;
    fmt.width = width;
    fmt.height = height;
    fmt.fourcc = FourCC::new(fourcc);
    let fmt = dev.set_format(&fmt).map_err(SpikeError::V4l)?;
    if fmt.width != width || fmt.height != height {
        return Err(SpikeError::Invalid(format!(
            "{path}: driver gave {}x{} instead of {width}x{height}",
            fmt.width, fmt.height
        )));
    }
    let mut stream =
        MmapStream::with_buffers(&dev, Type::VideoCapture, 4).map_err(SpikeError::V4l)?;
    let mut last: Vec<u8> = Vec::new();
    for _ in 0..=warmup {
        let (buf, _meta) = stream.next().map_err(SpikeError::V4l)?;
        last = buf.to_vec();
    }
    Ok((last, fmt))
}

pub fn capture_rgb() -> Result<RgbImage> {
    let (buf, _fmt) = grab_frame(RGB_PATH, b"MJPG", 640, 480, WARMUP_FRAMES)?;
    let img = image::load_from_memory(&buf)?;
    Ok(img.to_rgb8())
}

pub fn capture_ir() -> Result<GrayImage> {
    let (buf, fmt) = grab_frame(IR_PATH, b"GREY", 640, 360, WARMUP_FRAMES)?;
    let (w, h) = (fmt.width as usize, fmt.height as usize);
    let stride = fmt.stride as usize;
    if stride < w || buf.len() < stride * (h - 1) + w {
        return Err(SpikeError::Invalid(format!(
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
        .ok_or_else(|| SpikeError::Invalid("IR pixel buffer size mismatch".into()))
}

pub fn capture_paired() -> Result<PairedCapture> {
    let rgb = capture_rgb()?;
    let ir = capture_ir()?;
    Ok(PairedCapture { rgb, ir })
}

/// Mean pixel brightness, 0..255.
pub fn mean_brightness_rgb(img: &RgbImage) -> f64 {
    if img.width() == 0 || img.height() == 0 {
        return 0.0;
    }
    let sum: u64 = img
        .pixels()
        .map(|p| p[0] as u64 + p[1] as u64 + p[2] as u64)
        .sum();
    sum as f64 / (img.pixels().count() as f64 * 3.0)
}

pub fn mean_brightness_gray(img: &GrayImage) -> f64 {
    if img.width() == 0 || img.height() == 0 {
        return 0.0;
    }
    let sum: u64 = img.pixels().map(|p| p[0] as u64).sum();
    sum as f64 / img.pixels().count() as f64
}

/// Replicate a grayscale image into 3 RGB channels (for SFace on IR).
pub fn gray_to_rgb(img: &GrayImage) -> RgbImage {
    RgbImage::from_fn(img.width(), img.height(), |x, y| {
        let v = img.get_pixel(x, y)[0];
        image::Rgb([v, v, v])
    })
}

pub fn load_image_rgb(path: &Path) -> Result<RgbImage> {
    let img = image::ImageReader::open(path)
        .map_err(|e| crate::error::io_at(path, e))?
        .decode()?;
    Ok(img.to_rgb8())
}
