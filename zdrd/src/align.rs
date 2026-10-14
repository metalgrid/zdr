//! Face alignment math for SFace, mirroring OpenCV `FaceRecognizerSF`:
//! estimate the similarity transform from the 5 YuNet landmarks to the
//! 112x112 reference points, then warp with bilinear sampling.
//! Pure functions: unit-testable without the model or a camera.

use crate::error::{DaemonError, Result};
use image::RgbImage;

/// SFace reference landmarks in a 112x112 crop (OpenCV face_recognize.cpp).
pub const REFERENCE: [[f32; 2]; 5] = [
    [38.2946, 51.6963],
    [73.5318, 51.5014],
    [56.0252, 71.7366],
    [41.5493, 92.3655],
    [70.7299, 92.2041],
];

/// 2x3 affine matrix `[a b tx; c d ty]` mapping source -> destination.
pub type Affine = [f32; 6];

fn mean(points: &[[f32; 2]; 5]) -> [f64; 2] {
    let mut m = [0.0f64; 2];
    for p in points {
        m[0] += p[0] as f64;
        m[1] += p[1] as f64;
    }
    [m[0] / 5.0, m[1] / 5.0]
}

/// Least-squares similarity transform (rotation + uniform scale +
/// translation, no reflection) mapping `src` onto `dst`. This is the
/// Umeyama solution restricted to proper rotations, computed in complex
/// form: multiplier = sum(dst_d * conj(src_d)) / sum(|src_d|^2).
pub fn similarity_transform(src: &[[f32; 2]; 5], dst: &[[f32; 2]; 5]) -> Result<Affine> {
    let sm = mean(src);
    let dm = mean(dst);
    let (mut num_re, mut num_im, mut den) = (0.0f64, 0.0f64, 0.0f64);
    for i in 0..5 {
        let sx = src[i][0] as f64 - sm[0];
        let sy = src[i][1] as f64 - sm[1];
        let dx = dst[i][0] as f64 - dm[0];
        let dy = dst[i][1] as f64 - dm[1];
        // (dx + i dy) * conj(sx + i sy)
        num_re += dx * sx + dy * sy;
        num_im += dy * sx - dx * sy;
        den += sx * sx + sy * sy;
    }
    if den < 1e-12 {
        return Err(DaemonError::Invalid(
            "degenerate landmarks (zero spread)".into(),
        ));
    }
    let a = num_re / den;
    let b = num_im / den;
    // dst = M * src + t, M = [[a, -b], [b, a]] in complex form.
    let tx = dm[0] - (a * sm[0] - b * sm[1]);
    let ty = dm[1] - (b * sm[0] + a * sm[1]);
    Ok([
        a as f32,
        (-b) as f32,
        tx as f32,
        b as f32,
        a as f32,
        ty as f32,
    ])
}

pub fn apply(m: &Affine, p: [f32; 2]) -> [f32; 2] {
    [
        m[0] * p[0] + m[1] * p[1] + m[2],
        m[3] * p[0] + m[4] * p[1] + m[5],
    ]
}

pub fn invert(m: &Affine) -> Result<Affine> {
    let det = m[0] * m[4] - m[1] * m[3];
    if det.abs() < 1e-12 {
        return Err(DaemonError::Invalid("singular alignment transform".into()));
    }
    let ia = m[4] / det;
    let ib = -m[1] / det;
    let ic = -m[3] / det;
    let id = m[0] / det;
    Ok([
        ia,
        ib,
        -(ia * m[2] + ib * m[5]),
        ic,
        id,
        -(ic * m[2] + id * m[5]),
    ])
}

fn sample_bilinear(img: &RgbImage, x: f32, y: f32) -> [u8; 3] {
    let (w, h) = (img.width() as i64, img.height() as i64);
    let x0 = x.floor() as i64;
    let y0 = y.floor() as i64;
    let fx = x - x0 as f32;
    let fy = y - y0 as f32;
    let mut out = [0u8; 3];
    for (ch, o) in out.iter_mut().enumerate() {
        let mut acc = 0.0f32;
        for (dx, dy, weight) in [
            (0i64, 0i64, (1.0 - fx) * (1.0 - fy)),
            (1, 0, fx * (1.0 - fy)),
            (0, 1, (1.0 - fx) * fy),
            (1, 1, fx * fy),
        ] {
            let (px, py) = (x0 + dx, y0 + dy);
            if px >= 0 && py >= 0 && px < w && py < h {
                acc += weight * img.get_pixel(px as u32, py as u32)[ch] as f32;
            }
        }
        *o = acc.round().clamp(0.0, 255.0) as u8;
    }
    out
}

/// Warp `img` into a 112x112 aligned crop using the forward transform
/// `m` (source landmark space -> 112x112 space), like `cv::warpAffine`
/// with INTER_LINEAR and a zero border.
pub fn warp_to_112(img: &RgbImage, m: &Affine) -> Result<RgbImage> {
    let inv = invert(m)?;
    let mut out = RgbImage::new(112, 112);
    for y in 0..112u32 {
        for x in 0..112u32 {
            let src = apply(&inv, [x as f32, y as f32]);
            out.put_pixel(x, y, image::Rgb(sample_bilinear(img, src[0], src[1])));
        }
    }
    Ok(out)
}

/// Align a face in `img` from its 5 landmarks to the SFace 112x112 crop.
pub fn align_face(img: &RgbImage, landmarks: &[[f32; 2]; 5]) -> Result<RgbImage> {
    let m = similarity_transform(landmarks, &REFERENCE)?;
    warp_to_112(img, &m)
}

/// Cosine similarity. Returns 0.0 for mismatched lengths or zero norms.
pub fn cosine(a: &[f32], b: &[f32]) -> f32 {
    if a.len() != b.len() || a.is_empty() {
        return 0.0;
    }
    let (mut dot, mut na, mut nb) = (0.0f64, 0.0f64, 0.0f64);
    for i in 0..a.len() {
        dot += a[i] as f64 * b[i] as f64;
        na += (a[i] as f64).powi(2);
        nb += (b[i] as f64).powi(2);
    }
    if na <= 0.0 || nb <= 0.0 {
        return 0.0;
    }
    (dot / (na.sqrt() * nb.sqrt())) as f32
}

/// L2-normalize in place style: returns (normalized vector, original norm).
pub fn l2_normalize(v: &[f32]) -> Result<(Vec<f32>, f32)> {
    let norm = v.iter().map(|x| (*x as f64).powi(2)).sum::<f64>().sqrt();
    if norm <= 0.0 {
        return Err(DaemonError::Invalid(
            "cannot normalize zero embedding".into(),
        ));
    }
    let out = v.iter().map(|x| (*x as f64 / norm) as f32).collect();
    Ok((out, norm as f32))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cosine_basics() {
        assert!((cosine(&[1.0, 0.0], &[1.0, 0.0]) - 1.0).abs() < 1e-6);
        assert!((cosine(&[1.0, 0.0], &[0.0, 1.0])).abs() < 1e-6);
        assert!((cosine(&[1.0, 0.0], &[-1.0, 0.0]) + 1.0).abs() < 1e-6);
        assert!((cosine(&[3.0, 4.0], &[3.0, 4.0]) - 1.0).abs() < 1e-6);
        assert_eq!(cosine(&[0.0, 0.0], &[1.0, 1.0]), 0.0);
        assert_eq!(cosine(&[1.0], &[1.0, 2.0]), 0.0);
    }

    #[test]
    fn normalize_gives_unit_norm() {
        let (n, raw) = l2_normalize(&[3.0, 4.0]).expect("nonzero");
        assert!((raw - 5.0).abs() < 1e-6);
        assert!((cosine(&n, &n) - 1.0).abs() < 1e-6);
        assert!(l2_normalize(&[0.0, 0.0]).is_err());
    }

    #[test]
    fn similarity_of_reference_is_identity() {
        let m = similarity_transform(&REFERENCE, &REFERENCE).expect("ok");
        for p in REFERENCE {
            let q = apply(&m, p);
            assert!((q[0] - p[0]).abs() < 1e-3, "x: {} vs {}", q[0], p[0]);
            assert!((q[1] - p[1]).abs() < 1e-3, "y: {} vs {}", q[1], p[1]);
        }
    }

    #[test]
    fn similarity_recovers_known_transform() {
        // Build src by applying scale 2, rotation 30deg, translation (10,-5)
        // to the reference; the estimated src->reference transform must
        // map every src point back onto the reference.
        let (s, th) = (2.0f32, 30.0f32.to_radians());
        let fwd: Affine = [
            s * th.cos(),
            -s * th.sin(),
            10.0,
            s * th.sin(),
            s * th.cos(),
            -5.0,
        ];
        let src: [[f32; 2]; 5] = std::array::from_fn(|i| apply(&fwd, REFERENCE[i]));
        let est = similarity_transform(&src, &REFERENCE).expect("ok");
        for i in 0..5 {
            let q = apply(&est, src[i]);
            assert!((q[0] - REFERENCE[i][0]).abs() < 1e-2, "point {i} x");
            assert!((q[1] - REFERENCE[i][1]).abs() < 1e-2, "point {i} y");
        }
    }

    #[test]
    fn warp_with_identity_copies_image() {
        let img = RgbImage::from_fn(112, 112, |x, y| {
            image::Rgb([(x % 256) as u8, (y % 256) as u8, 128])
        });
        let identity: Affine = [1.0, 0.0, 0.0, 0.0, 1.0, 0.0];
        let out = warp_to_112(&img, &identity).expect("ok");
        assert_eq!(out.get_pixel(10, 20), &image::Rgb([10, 20, 128]));
        assert_eq!(out.get_pixel(111, 111), &image::Rgb([111, 111, 128]));
    }
}
