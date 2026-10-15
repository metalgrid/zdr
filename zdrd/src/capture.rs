//! Paired camera capture via V4L2 (ported from the Phase 0 spike).
//!
//! - RGB: MJPG 640x480.
//! - IR: GREY 640x360 raw.
//! Device paths are supplied by the caller (stable /dev/v4l/by-path defaults in args).
//!
//! GREY is headerless Luma8: copy row by row using the format stride.
//! Warm-up is adaptive: at least 3 frames are always taken, then capture
//! stops as soon as the mean brightness settles (see [`WarmupSettler`]),
//! and never takes more than 11 frames per sensor. Never capture above
//! 640 wide.

use crate::error::{DaemonError, Result};
use image::{GrayImage, RgbImage};
use std::path::Path;
use v4l::buffer::Type;
use v4l::io::mmap::Stream as MmapStream;
use v4l::io::traits::CaptureStream;
use v4l::video::Capture;
use v4l::{Device, FourCC};

/// Minimum frames taken per sensor before settling may stop capture.
pub const MIN_WARMUP_FRAMES: usize = 3;
/// Hard cap on frames per sensor (the old fixed 10 discards + 1 kept).
pub const MAX_CAPTURE_FRAMES: usize = 11;
/// Brightness change (0-255 scale) at or below which capture is settled.
pub const SETTLE_TOLERANCE: f64 = 2.0;

/// Why a warm-up loop stopped, or that it should keep going.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WarmupOutcome {
    Continue,
    Settled,
    Capped,
}

/// Pure stability-based stopping rule for warm-up, fed one mean
/// brightness (0-255) per captured frame. Stops early once at least
/// [`MIN_WARMUP_FRAMES`] frames have been seen and the last two means
/// differ by at most [`SETTLE_TOLERANCE`]; never exceeds
/// [`MAX_CAPTURE_FRAMES`].
#[derive(Debug, Default)]
pub struct WarmupSettler {
    frames: usize,
    last_mean: Option<f64>,
}

impl WarmupSettler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Frames fed so far.
    pub fn frames(&self) -> usize {
        self.frames
    }

    /// Feed one frame's mean brightness; returns whether to stop.
    pub fn observe(&mut self, mean: f64) -> WarmupOutcome {
        self.frames += 1;
        let stable = self.frames >= MIN_WARMUP_FRAMES
            && matches!(self.last_mean, Some(prev) if (mean - prev).abs() <= SETTLE_TOLERANCE);
        self.last_mean = Some(mean);
        if stable {
            WarmupOutcome::Settled
        } else if self.frames >= MAX_CAPTURE_FRAMES {
            WarmupOutcome::Capped
        } else {
            WarmupOutcome::Continue
        }
    }
}

/// Mean brightness of a GREY frame, stride-aware: only the `width`
/// pixels of each row count, never the stride padding.
fn grey_mean(buf: &[u8], stride: usize, width: usize, height: usize) -> f64 {
    let (mut sum, mut count) = (0u64, 0usize);
    for y in 0..height {
        let start = y * stride;
        if start >= buf.len() {
            break;
        }
        let row = &buf[start..buf.len().min(start + width)];
        sum += row.iter().map(|&b| b as u64).sum::<u64>();
        count += row.len();
    }
    if count == 0 {
        0.0
    } else {
        sum as f64 / count as f64
    }
}

/// Mean luma (Rec. 601) of a decoded RGB frame, on the 0-255 scale.
fn rgb_mean(img: &RgbImage) -> f64 {
    if img.is_empty() {
        return 0.0;
    }
    let sum: f64 = img
        .pixels()
        .map(|p| 0.299 * p[0] as f64 + 0.587 * p[1] as f64 + 0.114 * p[2] as f64)
        .sum();
    sum / (img.width() as f64 * img.height() as f64)
}

pub struct PairedCapture {
    pub rgb: RgbImage,
    pub ir: GrayImage,
}

/// The frame kept from a stream: raw bytes for GREY, or the already
/// decoded image for MJPG (so the kept frame is not decoded twice).
enum GrabbedFrame {
    Raw(Vec<u8>),
    Decoded(RgbImage),
}

/// Capture frames from `path` until brightness settles (or the cap),
/// keeping the last one. `sensor` labels the log line ("rgb"/"ir");
/// MJPG streams are decoded per frame for their luma mean.
fn grab_frame(
    path: &str,
    fourcc: &[u8; 4],
    width: u32,
    height: u32,
    sensor: &str,
    decode_mjpg: bool,
) -> Result<(GrabbedFrame, v4l::Format)> {
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
    let mut settler = WarmupSettler::new();
    let (last, outcome) = loop {
        let (buf, _meta) = stream.next().map_err(DaemonError::V4l)?;
        let (mean, frame) = if decode_mjpg {
            let img = image::load_from_memory(buf)?.to_rgb8();
            (rgb_mean(&img), GrabbedFrame::Decoded(img))
        } else {
            (
                grey_mean(
                    buf,
                    fmt.stride as usize,
                    fmt.width as usize,
                    fmt.height as usize,
                ),
                GrabbedFrame::Raw(buf.to_vec()),
            )
        };
        let outcome = settler.observe(mean);
        if outcome != WarmupOutcome::Continue {
            break (frame, outcome);
        }
    };
    eprintln!(
        "zdrd: capture {sensor} frames={} settle={}",
        settler.frames(),
        if outcome == WarmupOutcome::Settled {
            "early"
        } else {
            "cap"
        }
    );
    Ok((last, fmt))
}

pub fn capture_rgb(path: &str) -> Result<RgbImage> {
    match grab_frame(path, b"MJPG", 640, 480, "rgb", true)? {
        (GrabbedFrame::Decoded(img), _) => Ok(img),
        (GrabbedFrame::Raw(_), _) => Err(DaemonError::Invalid(
            "RGB capture returned an undecoded frame".into(),
        )),
    }
}

pub fn capture_ir(path: &str) -> Result<GrayImage> {
    let (frame, fmt) = grab_frame(path, b"GREY", 640, 360, "ir", false)?;
    let buf = match frame {
        GrabbedFrame::Raw(buf) => buf,
        GrabbedFrame::Decoded(_) => {
            return Err(DaemonError::Invalid(
                "IR capture returned a decoded frame".into(),
            ))
        }
    };
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Feed a synthetic brightness series, returning (frames taken, outcome).
    fn run(series: &[f64]) -> (usize, WarmupOutcome) {
        let mut settler = WarmupSettler::new();
        let mut outcome = WarmupOutcome::Continue;
        for &mean in series {
            outcome = settler.observe(mean);
            if outcome != WarmupOutcome::Continue {
                break;
            }
        }
        (settler.frames(), outcome)
    }

    #[test]
    fn flat_series_stops_at_minimum() {
        let (frames, outcome) = run(&[100.0; 11]);
        assert_eq!(frames, MIN_WARMUP_FRAMES);
        assert_eq!(outcome, WarmupOutcome::Settled);
    }

    #[test]
    fn stability_before_minimum_does_not_stop() {
        let mut settler = WarmupSettler::new();
        assert_eq!(settler.observe(100.0), WarmupOutcome::Continue);
        // Identical means, but only frame 2: the minimum has not been met.
        assert_eq!(settler.observe(100.0), WarmupOutcome::Continue);
        assert_eq!(settler.observe(100.0), WarmupOutcome::Settled);
    }

    #[test]
    fn converging_series_stops_early() {
        // Settles as soon as the frame-to-frame change drops to <= 2.0.
        let (frames, outcome) = run(&[10.0, 40.0, 70.0, 71.5, 71.6, 71.6]);
        assert_eq!(frames, 4);
        assert_eq!(outcome, WarmupOutcome::Settled);
        // Exactly at the tolerance also settles; just above it does not.
        let (frames, outcome) = run(&[0.0, 50.0, 90.0, 92.0]);
        assert_eq!((frames, outcome), (4, WarmupOutcome::Settled));
        let (frames, outcome) = run(&[0.0, 50.0, 90.0, 92.1, 92.2]);
        assert_eq!((frames, outcome), (5, WarmupOutcome::Settled));
    }

    #[test]
    fn unstable_series_hits_cap() {
        let series: Vec<f64> = (0..20)
            .map(|i| if i % 2 == 0 { 20.0 } else { 200.0 })
            .collect();
        let (frames, outcome) = run(&series);
        assert_eq!(frames, MAX_CAPTURE_FRAMES);
        assert_eq!(outcome, WarmupOutcome::Capped);
    }

    #[test]
    fn grey_mean_ignores_stride_padding() {
        // 3x2 frame, stride 5: padding bytes (255) must not count.
        let buf: Vec<u8> = vec![
            10, 20, 30, 255, 255, //
            40, 50, 60, 255, 255,
        ];
        assert!((grey_mean(&buf, 5, 3, 2) - 35.0).abs() < 1e-9);
        assert_eq!(grey_mean(&[], 5, 3, 2), 0.0);
    }
}
