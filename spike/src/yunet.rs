//! YuNet output decoding, mirroring OpenCV `FaceDetectorYN`
//! (modules/objdetect/src/face_detect.cpp). Pure functions: unit-testable
//! without the model or a camera.
//!
//! For each stride in {8, 16, 32} the model emits four tensors over the
//! padded feature grid (rows = padH/stride, cols = padW/stride):
//! `cls`, `obj` (1 channel), `bbox` (4), `kps` (10 = 5 landmarks).
//! score = sqrt(clamp(cls) * clamp(obj)); box centre = (cell + bbox.xy) *
//! stride; size = exp(bbox.wh) * stride; landmark = (kps + cell) * stride.

/// One detected face. Landmark order (as emitted by YuNet):
/// right eye, left eye, nose tip, right mouth corner, left mouth corner.
#[derive(Debug, Clone, PartialEq)]
pub struct Face {
    pub x: f32,
    pub y: f32,
    pub w: f32,
    pub h: f32,
    pub landmarks: [[f32; 2]; 5],
    pub score: f32,
}

impl Face {
    pub fn area(&self) -> f32 {
        self.w.max(0.0) * self.h.max(0.0)
    }
}

/// Raw per-stride YuNet outputs (flat, row-major over the feature grid).
pub struct StrideOutputs<'a> {
    pub stride: u32,
    pub rows: usize,
    pub cols: usize,
    pub cls: &'a [f32],
    pub obj: &'a [f32],
    pub bbox: &'a [f32],
    pub kps: &'a [f32],
}

fn iou(a: &Face, b: &Face) -> f32 {
    let x1 = a.x.max(b.x);
    let y1 = a.y.max(b.y);
    let x2 = (a.x + a.w).min(b.x + b.w);
    let y2 = (a.y + a.h).min(b.y + b.h);
    let inter = (x2 - x1).max(0.0) * (y2 - y1).max(0.0);
    let union = a.area() + b.area() - inter;
    if union <= 0.0 {
        0.0
    } else {
        inter / union
    }
}

/// Decode all strides, threshold, then greedy NMS (highest score first),
/// keeping at most `top_k` faces. Returned faces are score-descending.
pub fn decode(
    strides: &[StrideOutputs<'_>],
    score_threshold: f32,
    nms_threshold: f32,
    top_k: usize,
) -> Vec<Face> {
    let mut candidates: Vec<Face> = Vec::new();
    for s in strides {
        let cells = s.rows * s.cols;
        for r in 0..s.rows {
            for c in 0..s.cols {
                let idx = r * s.cols + c;
                if idx >= s.cls.len() || idx >= s.obj.len() {
                    continue;
                }
                let cls = s.cls[idx].clamp(0.0, 1.0);
                let obj = s.obj[idx].clamp(0.0, 1.0);
                let score = (cls * obj).sqrt();
                if score < score_threshold {
                    continue;
                }
                let b = idx * 4;
                let k = idx * 10;
                if b + 3 >= s.bbox.len() || k + 9 >= s.kps.len() {
                    continue;
                }
                let stride = s.stride as f32;
                let cx = (c as f32 + s.bbox[b]) * stride;
                let cy = (r as f32 + s.bbox[b + 1]) * stride;
                let w = s.bbox[b + 2].exp() * stride;
                let h = s.bbox[b + 3].exp() * stride;
                let mut landmarks = [[0.0f32; 2]; 5];
                for (n, lm) in landmarks.iter_mut().enumerate() {
                    *lm = [
                        (s.kps[k + 2 * n] + c as f32) * stride,
                        (s.kps[k + 2 * n + 1] + r as f32) * stride,
                    ];
                }
                let _ = cells;
                candidates.push(Face {
                    x: cx - w / 2.0,
                    y: cy - h / 2.0,
                    w,
                    h,
                    landmarks,
                    score,
                });
            }
        }
    }

    candidates.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    let mut kept: Vec<Face> = Vec::new();
    for cand in candidates {
        if kept.iter().all(|k: &Face| iou(k, &cand) <= nms_threshold) {
            kept.push(cand);
            if kept.len() >= top_k {
                break;
            }
        }
    }
    kept
}

#[cfg(test)]
mod tests {
    use super::*;

    fn zeros(n: usize) -> Vec<f32> {
        vec![0.0; n]
    }

    #[test]
    fn decodes_single_cell_like_opencv() {
        // stride 8, 2x2 grid. Hot cell at (r=1, c=1): bbox offsets 0,
        // so centre = (1,1)*8 = (8,8), size = exp(0)*8 = 8, box = (4,4,8,8).
        let mut cls = zeros(4);
        let mut obj = zeros(4);
        let bbox = zeros(16);
        let kps = zeros(40);
        cls[3] = 1.0;
        obj[3] = 0.81; // score = sqrt(0.81) = 0.9
        let out = decode(
            &[StrideOutputs {
                stride: 8,
                rows: 2,
                cols: 2,
                cls: &cls,
                obj: &obj,
                bbox: &bbox,
                kps: &kps,
            }],
            0.6,
            0.3,
            5000,
        );
        assert_eq!(out.len(), 1);
        let f = &out[0];
        assert!((f.score - 0.9).abs() < 1e-6);
        assert!((f.x - 4.0).abs() < 1e-6 && (f.y - 4.0).abs() < 1e-6);
        assert!((f.w - 8.0).abs() < 1e-6 && (f.h - 8.0).abs() < 1e-6);
        // Landmarks: (0 + cell) * stride = (8, 8) for every point.
        for lm in f.landmarks {
            assert!((lm[0] - 8.0).abs() < 1e-6 && (lm[1] - 8.0).abs() < 1e-6);
        }
    }

    #[test]
    fn threshold_rejects_low_scores() {
        let mut cls = zeros(1);
        let mut obj = zeros(1);
        cls[0] = 0.25;
        obj[0] = 0.25; // score 0.25 < 0.6
        let out = decode(
            &[StrideOutputs {
                stride: 8,
                rows: 1,
                cols: 1,
                cls: &cls,
                obj: &obj,
                bbox: &zeros(4),
                kps: &zeros(10),
            }],
            0.6,
            0.3,
            5000,
        );
        assert!(out.is_empty());
    }

    #[test]
    fn nms_suppresses_overlapping_lower_score() {
        // Two adjacent cells, same big box after decode, scores 1.0 and 0.9.
        let mut cls = zeros(2);
        let mut obj = zeros(2);
        let mut bbox = zeros(8);
        cls[0] = 1.0;
        obj[0] = 1.0;
        cls[1] = 0.9;
        obj[1] = 0.9;
        // Cell 1 centre x should also be 4: (1 + bbox0)*8 = 4 -> bbox0 = -0.5
        bbox[4] = -0.5;
        // exp(ln(4)) = 4 -> w = h = 32 for both, identical boxes.
        bbox[2] = 4.0f32.ln();
        bbox[3] = 4.0f32.ln();
        bbox[6] = 4.0f32.ln();
        bbox[7] = 4.0f32.ln();
        let out = decode(
            &[StrideOutputs {
                stride: 8,
                rows: 1,
                cols: 2,
                cls: &cls,
                obj: &obj,
                bbox: &bbox,
                kps: &zeros(20),
            }],
            0.6,
            0.3,
            5000,
        );
        assert_eq!(out.len(), 1);
        assert!((out[0].score - 1.0).abs() < 1e-6);
    }
}
