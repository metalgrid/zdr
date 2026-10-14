//! Camera auto-detection (Step 14).
//!
//! Scan `/dev/v4l/by-path/*` symlinks (falling back to `/dev/video*`
//! when the by-path directory is absent), resolve each to its
//! `/dev/videoN` target, and probe each unique device's offered
//! formats with V4L2 format enumeration only — read-only, never
//! streaming.
//!
//! Classification (pure, unit-tested with fake format lists):
//! - IR candidate: offers `GREY` and no `MJPG`.
//! - RGB candidate: offers `MJPG`.
//! The deterministic tie-break is the lowest by-path name among the
//! candidates (probes are sorted by link path before selection).

use std::path::{Path, PathBuf};
use v4l::video::Capture;
use v4l::Device;

/// One probed device: the name it was found under, the resolved
/// `/dev/videoN` target, and the FourCC strings it offers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceProbe {
    pub link: PathBuf,
    pub target: PathBuf,
    pub formats: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SensorKind {
    Rgb,
    Ir,
    Unknown,
}

/// Classify one device from its offered FourCC strings.
pub fn classify(formats: &[String]) -> SensorKind {
    let has = |want: &str| formats.iter().any(|f| f.eq_ignore_ascii_case(want));
    if has("MJPG") {
        SensorKind::Rgb
    } else if has("GREY") {
        SensorKind::Ir
    } else {
        SensorKind::Unknown
    }
}

/// Auto-detection result: the chosen device paths (the by-path link,
/// which is stable across reboots) plus a human-readable summary of
/// every probed device for startup logging.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DetectedCameras {
    pub rgb: Option<PathBuf>,
    pub ir: Option<PathBuf>,
    pub summary: Vec<String>,
}

/// Pick cameras from probe data. Deterministic: probes are considered
/// in ascending link-path order and duplicate targets (the several
/// by-path names / interfaces of one physical device) count once.
pub fn select(probes: &[DeviceProbe]) -> DetectedCameras {
    let mut ordered: Vec<&DeviceProbe> = probes.iter().collect();
    ordered.sort_by(|a, b| a.link.cmp(&b.link));
    let mut seen_targets: Vec<&Path> = Vec::new();
    let mut detected = DetectedCameras::default();
    for probe in ordered {
        if seen_targets.contains(&probe.target.as_path()) {
            continue;
        }
        seen_targets.push(probe.target.as_path());
        let kind = classify(&probe.formats);
        let kind_label = match kind {
            SensorKind::Rgb => "RGB candidate",
            SensorKind::Ir => "IR candidate",
            SensorKind::Unknown => "not a face camera",
        };
        detected.summary.push(format!(
            "{} -> {}: formats [{}] => {kind_label}",
            probe.link.display(),
            probe.target.display(),
            probe.formats.join(", ")
        ));
        match kind {
            SensorKind::Rgb => {
                if detected.rgb.is_none() {
                    detected.rgb = Some(probe.link.clone());
                }
            }
            SensorKind::Ir => {
                if detected.ir.is_none() {
                    detected.ir = Some(probe.link.clone());
                }
            }
            SensorKind::Unknown => {}
        }
    }
    detected
}

/// Enumerate the format FourCC strings offered by one device.
/// Read-only: opens the node and runs VIDIOC_ENUM_FMT; no format is
/// set and no stream is started.
fn probe_formats(path: &Path) -> Vec<String> {
    let dev = match Device::with_path(path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("zdrd: camfind: cannot open {}: {e}", path.display());
            return Vec::new();
        }
    };
    match dev.enum_formats() {
        Ok(descriptions) => descriptions
            .iter()
            .map(|d| d.fourcc.to_string().trim().to_string())
            .collect(),
        Err(e) => {
            eprintln!(
                "zdrd: camfind: cannot enumerate formats on {}: {e}",
                path.display()
            );
            Vec::new()
        }
    }
}

fn probes_from_links(links: &[PathBuf]) -> Vec<DeviceProbe> {
    let mut probes = Vec::new();
    for link in links {
        let target = match std::fs::canonicalize(link) {
            Ok(t) => t,
            Err(e) => {
                eprintln!(
                    "zdrd: camfind: cannot resolve {}: {e}",
                    link.display()
                );
                continue;
            }
        };
        let formats = probe_formats(link);
        probes.push(DeviceProbe {
            link: link.clone(),
            target,
            formats,
        });
    }
    probes
}

fn sorted_dir_entries(dir: &Path) -> Vec<PathBuf> {
    let mut entries: Vec<PathBuf> = match std::fs::read_dir(dir) {
        Ok(rd) => rd.filter_map(|e| e.ok().map(|e| e.path())).collect(),
        Err(_) => Vec::new(),
    };
    entries.sort();
    entries
}

/// Probe the real system. Absent `/dev/v4l/by-path` (or an empty one)
/// falls back to scanning `/dev/video*` directly.
pub fn detect() -> DetectedCameras {
    let by_path = Path::new("/dev/v4l/by-path");
    let links = if by_path.is_dir() {
        sorted_dir_entries(by_path)
    } else {
        Vec::new()
    };
    if !links.is_empty() {
        return select(&probes_from_links(&links));
    }
    eprintln!("zdrd: camfind: /dev/v4l/by-path unavailable, falling back to /dev/video*");
    let videos: Vec<PathBuf> = sorted_dir_entries(Path::new("/dev"))
        .into_iter()
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .map(|n| {
                    n.starts_with("video")
                        && n["video".len()..].chars().all(|c| c.is_ascii_digit())
                        && n.len() > "video".len()
                })
                .unwrap_or(false)
        })
        .collect();
    // With no by-path links the device node itself is both link and target.
    let probes: Vec<DeviceProbe> = videos
        .iter()
        .map(|v| DeviceProbe {
            link: v.clone(),
            target: v.clone(),
            formats: probe_formats(v),
        })
        .collect();
    select(&probes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn probe(link: &str, target: &str, formats: &[&str]) -> DeviceProbe {
        DeviceProbe {
            link: PathBuf::from(link),
            target: PathBuf::from(target),
            formats: formats.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn classification_rules() {
        assert_eq!(classify(&["GREY".into()]), SensorKind::Ir);
        assert_eq!(classify(&["MJPG".into(), "YUYV".into()]), SensorKind::Rgb);
        // GREY + MJPG on one device: it is an RGB camera, not IR
        // (IR requires GREY *and no* MJPG).
        assert_eq!(classify(&["GREY".into(), "MJPG".into()]), SensorKind::Rgb);
        assert_eq!(classify(&["YUYV".into()]), SensorKind::Unknown);
        assert_eq!(classify(&[]), SensorKind::Unknown);
        assert_eq!(classify(&["mjpg".into()]), SensorKind::Rgb);
        assert_eq!(classify(&["grey".into()]), SensorKind::Ir);
    }

    #[test]
    fn lowest_by_path_name_wins_and_targets_dedupe() {
        let probes = vec![
            // Deliberately unordered input; index1 of the RGB device
            // resolves to the same target and must not double-count.
            probe("/dev/v4l/by-path/b-usb-0:1:1.0-video-index0", "/dev/video2", &["GREY"]),
            probe("/dev/v4l/by-path/a-usb-0:1:1.0-video-index1", "/dev/video0", &["MJPG"]),
            probe("/dev/v4l/by-path/a-usb-0:1:1.0-video-index0", "/dev/video0", &["MJPG", "YUYV"]),
            probe("/dev/v4l/by-path/c-usb-0:2:1.0-video-index0", "/dev/video4", &["GREY"]),
        ];
        let found = select(&probes);
        assert_eq!(
            found.rgb,
            Some(PathBuf::from("/dev/v4l/by-path/a-usb-0:1:1.0-video-index0"))
        );
        assert_eq!(
            found.ir,
            Some(PathBuf::from("/dev/v4l/by-path/b-usb-0:1:1.0-video-index0"))
        );
        // 4 links, 3 unique targets => 3 summary lines.
        assert_eq!(found.summary.len(), 3);
        assert!(found.summary[0].contains("RGB candidate"), "{}", found.summary[0]);
        assert!(found.summary[1].contains("IR candidate"), "{}", found.summary[1]);
    }

    #[test]
    fn no_candidates_yields_none() {
        let found = select(&[probe("/dev/video0", "/dev/video0", &["YUYV"])]);
        assert_eq!(found.rgb, None);
        assert_eq!(found.ir, None);
        let empty = select(&[]);
        assert_eq!(empty, DetectedCameras::default());
    }
}
