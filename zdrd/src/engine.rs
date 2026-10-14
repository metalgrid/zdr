//! ONNX engine: YuNet detection + SFace embedding via `ort`.
//!
//! Channel-order notes (from OpenCV's implementations):
//! - YuNet: OpenCV feeds the image as-is (BGR from `cv::imread`) with no
//!   swap. Our buffers are RGB, so we emit B, G, R planes, values 0..255.
//! - SFace: OpenCV calls `blobFromImage(..., swapRB=true)` on a BGR image,
//!   so the network actually sees R, G, B. Our buffers are RGB, so we emit
//!   R, G, B planes, values 0..255. No mean/scale in either model.

use crate::align;
use crate::error::{io_at, DaemonError, Result};
use crate::yunet::{self, Face, StrideOutputs};
use image::RgbImage;
use ort::session::Session;
use ort::value::Tensor;
use std::path::Path;

pub const SCORE_THRESHOLD: f32 = 0.6;
pub const NMS_THRESHOLD: f32 = 0.3;
const STRIDES: [u32; 3] = [8, 16, 32];

pub struct Embedding {
    /// L2-normalized embedding.
    pub vector: Vec<f32>,
    /// Norm before normalization (sanity signal; SFace raw output).
    pub raw_norm: f32,
}

/// Detection + embedding behind one trait so tests can drive the
/// capture-verify logic with a mock engine and no models or cameras.
pub trait FaceEngine: Send {
    /// Detect faces in an RGB image, best score first.
    fn detect(&mut self, img: &RgbImage) -> Result<Vec<Face>>;
    /// Align `face` in `img` and embed it.
    fn embed_face(&mut self, img: &RgbImage, face: &Face) -> Result<Embedding>;
    /// Detect and embed the largest face (by box area).
    fn embed_largest(&mut self, img: &RgbImage) -> Result<(Face, Embedding)> {
        let faces = self.detect(img)?;
        let face = faces
            .into_iter()
            .max_by(|a, b| {
                a.area()
                    .partial_cmp(&b.area())
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .ok_or_else(|| DaemonError::NoFace("no face detected in image".into()))?;
        let emb = self.embed_face(img, &face)?;
        Ok((face, emb))
    }
}

pub struct OnnxEngine {
    // Kept alive for the sessions' lifetime.
    _env: ort::environment::Environment,
    detector: Session,
    recognizer: Session,
    detector_input: String,
    recognizer_input: String,
}

fn load_session(env: &ort::environment::Environment, path: &Path) -> Result<Session> {
    if !path.is_file() {
        return Err(io_at(
            path,
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "model file missing; run scripts/download-models.sh",
            ),
        ));
    }
    let session = Session::builder(env)
        .map_err(DaemonError::from)?
        .commit_from_file(path)
        .map_err(DaemonError::from)?;
    Ok(session)
}

fn first_input_name(session: &Session, what: &str) -> Result<String> {
    session
        .inputs()
        .first()
        .map(|i| i.name().to_string())
        .ok_or_else(|| DaemonError::Model(format!("{what} model has no inputs")))
}

impl OnnxEngine {
    pub fn load(yunet_path: &Path, sface_path: &Path) -> Result<OnnxEngine> {
        let env = ort::init().build().map_err(DaemonError::from)?;
        let detector = load_session(&env, yunet_path)?;
        let recognizer = load_session(&env, sface_path)?;
        let detector_input = first_input_name(&detector, "YuNet")?;
        let recognizer_input = first_input_name(&recognizer, "SFace")?;
        Ok(OnnxEngine {
            _env: env,
            detector,
            recognizer,
            detector_input,
            recognizer_input,
        })
    }
}

impl FaceEngine for OnnxEngine {
    /// Run YuNet on an RGB image. Returns faces score-descending, in
    /// original image coordinates.
    ///
    /// The 2023mar ONNX export has a fixed 640x640 input, so the image is
    /// letterboxed (aspect preserved, zero padding bottom/right) into
    /// 640x640 and the decoded boxes/landmarks are mapped back.
    fn detect(&mut self, img: &RgbImage) -> Result<Vec<Face>> {
        const INPUT: u32 = 640;
        let (w, h) = (img.width(), img.height());
        if w == 0 || h == 0 {
            return Err(DaemonError::Invalid("empty image".into()));
        }
        let scale = (INPUT as f32 / w as f32)
            .min(INPUT as f32 / h as f32)
            .min(1.0);
        let (rw, rh) = (
            ((w as f32 * scale).round() as u32).max(1),
            ((h as f32 * scale).round() as u32).max(1),
        );
        let resized;
        let canvas_img: &RgbImage = if (rw, rh) == (w, h) {
            img
        } else {
            resized = image::imageops::resize(img, rw, rh, image::imageops::FilterType::Triangle);
            &resized
        };
        // NCHW float, BGR planes (see module docs), zero padding bottom/right.
        let plane = (INPUT * INPUT) as usize;
        let mut data = vec![0.0f32; 3 * plane];
        for y in 0..rh {
            for x in 0..rw {
                let p = canvas_img.get_pixel(x, y);
                let idx = (y * INPUT + x) as usize;
                data[idx] = p[2] as f32; // B
                data[plane + idx] = p[1] as f32; // G
                data[2 * plane + idx] = p[0] as f32; // R
            }
        }
        let tensor = Tensor::from_array(([1usize, 3, INPUT as usize, INPUT as usize], data))?;
        let outputs = self
            .detector
            .run(ort::inputs![self.detector_input.as_str() => tensor])?;

        // Extract all 12 outputs first (owned copies end the borrow).
        let mut tensors: Vec<Vec<f32>> = Vec::with_capacity(12);
        for name in output_names() {
            let value = outputs
                .get(name)
                .ok_or_else(|| DaemonError::Model(format!("YuNet output '{name}' missing")))?;
            let (_shape, slice) = value.try_extract_tensor::<f32>()?;
            tensors.push(slice.to_vec());
        }
        let mut stride_inputs = Vec::with_capacity(3);
        for (i, stride) in STRIDES.iter().enumerate() {
            let rows = (INPUT / stride) as usize;
            let cols = (INPUT / stride) as usize;
            let need = rows * cols;
            for (label, buf, ch) in [
                ("cls", &tensors[i], 1usize),
                ("obj", &tensors[3 + i], 1),
                ("bbox", &tensors[6 + i], 4),
                ("kps", &tensors[9 + i], 10),
            ] {
                if buf.len() < need * ch {
                    return Err(DaemonError::Model(format!(
                        "YuNet {label}_{stride} too small: {} < {}",
                        buf.len(),
                        need * ch
                    )));
                }
            }
            stride_inputs.push((rows, cols));
        }
        let views: Vec<StrideOutputs<'_>> = STRIDES
            .iter()
            .enumerate()
            .map(|(i, &stride)| StrideOutputs {
                stride,
                rows: stride_inputs[i].0,
                cols: stride_inputs[i].1,
                cls: &tensors[i],
                obj: &tensors[3 + i],
                bbox: &tensors[6 + i],
                kps: &tensors[9 + i],
            })
            .collect();
        let mut faces = yunet::decode(&views, SCORE_THRESHOLD, NMS_THRESHOLD, 5000);
        if (scale - 1.0).abs() > f32::EPSILON {
            for f in &mut faces {
                f.x /= scale;
                f.y /= scale;
                f.w /= scale;
                f.h /= scale;
                for lm in &mut f.landmarks {
                    lm[0] /= scale;
                    lm[1] /= scale;
                }
            }
        }
        Ok(faces)
    }

    /// Align `face` in `img` to 112x112 and run SFace.
    fn embed_face(&mut self, img: &RgbImage, face: &Face) -> Result<Embedding> {
        let aligned = align::align_face(img, &face.landmarks)?;
        self.embed_aligned(&aligned)
    }
}

impl OnnxEngine {
    /// Run SFace on an already-aligned 112x112 RGB crop.
    pub fn embed_aligned(&mut self, aligned: &RgbImage) -> Result<Embedding> {
        if aligned.width() != 112 || aligned.height() != 112 {
            return Err(DaemonError::Invalid(format!(
                "SFace input must be 112x112, got {}x{}",
                aligned.width(),
                aligned.height()
            )));
        }
        let plane = 112 * 112usize;
        let mut data = vec![0.0f32; 3 * plane];
        for y in 0..112u32 {
            for x in 0..112u32 {
                let p = aligned.get_pixel(x, y);
                let idx = (y * 112 + x) as usize;
                data[idx] = p[0] as f32; // R (see module docs)
                data[plane + idx] = p[1] as f32; // G
                data[2 * plane + idx] = p[2] as f32; // B
            }
        }
        let tensor = Tensor::from_array(([1usize, 3, 112, 112], data))?;
        let outputs = self
            .recognizer
            .run(ort::inputs![self.recognizer_input.as_str() => tensor])?;
        let value = outputs
            .values()
            .next()
            .ok_or_else(|| DaemonError::Model("SFace produced no outputs".into()))?;
        let (_shape, slice) = value.try_extract_tensor::<f32>()?;
        if slice.is_empty() {
            return Err(DaemonError::Model("SFace embedding is empty".into()));
        }
        let (vector, raw_norm) = align::l2_normalize(slice)?;
        Ok(Embedding { vector, raw_norm })
    }
}

fn output_names() -> [&'static str; 12] {
    [
        "cls_8", "cls_16", "cls_32", "obj_8", "obj_16", "obj_32", "bbox_8", "bbox_16", "bbox_32",
        "kps_8", "kps_16", "kps_32",
    ]
}
