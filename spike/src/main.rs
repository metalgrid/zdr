use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};
use std::time::Instant;
use zdr_spike::error::{self, Result, SpikeError};
use zdr_spike::{align, capture, engine, yunet};

#[derive(Parser)]
#[command(
    name = "zdr-spike",
    about = "Phase 0 spike: YuNet + SFace on RGB + IR cameras"
)]
struct Cli {
    /// Directory containing the ONNX models.
    #[arg(long, default_value = "models", global = true)]
    model_dir: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Paired capture: RGB /dev/video0 MJPG 640x480 + IR GREY 640x360.
    Capture {
        /// Output directory for rgb.png and ir.png.
        #[arg(long, default_value = "captures")]
        out_dir: PathBuf,
    },
    /// Run YuNet on an image; print boxes, landmarks, scores.
    Detect {
        #[arg(long)]
        image: PathBuf,
    },
    /// Detect, align the largest face to 112x112, run SFace, print embedding stats.
    Embed {
        #[arg(long)]
        image: PathBuf,
    },
    /// Cosine similarity of the largest-face embeddings of two images.
    Compare {
        #[arg(long)]
        a: PathBuf,
        #[arg(long)]
        b: PathBuf,
    },
    /// Capture paired frames; compare live IR and RGB embeddings against enroll-dir images.
    VerifyLive {
        #[arg(long)]
        enroll_dir: PathBuf,
    },
    /// Per-stage latency (detect, align+embed) and peak RSS.
    Bench {
        #[arg(long)]
        image: PathBuf,
        #[arg(long, default_value_t = 50)]
        iters: usize,
    },
}

fn print_face(face: &yunet::Face) {
    println!(
        "box: x={:.1} y={:.1} w={:.1} h={:.1} score={:.4}",
        face.x, face.y, face.w, face.h, face.score
    );
    let names = ["right_eye", "left_eye", "nose", "right_mouth", "left_mouth"];
    for (name, lm) in names.iter().zip(face.landmarks.iter()) {
        println!("  {name}: ({:.1}, {:.1})", lm[0], lm[1]);
    }
}

fn cmd_capture(out_dir: &Path) -> Result<()> {
    std::fs::create_dir_all(out_dir).map_err(|e| error::io_at(out_dir, e))?;
    let paired = capture::capture_paired()?;
    let rgb_path = out_dir.join("rgb.png");
    let ir_path = out_dir.join("ir.png");
    paired.rgb.save(&rgb_path)?;
    paired.ir.save(&ir_path)?;
    println!(
        "rgb: {} ({}x{})",
        rgb_path.display(),
        paired.rgb.width(),
        paired.rgb.height()
    );
    println!(
        "ir:  {} ({}x{})",
        ir_path.display(),
        paired.ir.width(),
        paired.ir.height()
    );
    println!(
        "mean brightness rgb: {:.2} / 255",
        capture::mean_brightness_rgb(&paired.rgb)
    );
    println!(
        "mean brightness ir:  {:.2} / 255",
        capture::mean_brightness_gray(&paired.ir)
    );
    Ok(())
}

fn cmd_detect(model_dir: &Path, image: &Path) -> Result<()> {
    let img = capture::load_image_rgb(image)?;
    let mut eng = engine::Engine::load(model_dir)?;
    let faces = eng.detect(&img)?;
    println!("faces: {}", faces.len());
    for f in &faces {
        print_face(f);
    }
    Ok(())
}

fn cmd_embed(model_dir: &Path, image: &Path) -> Result<()> {
    let img = capture::load_image_rgb(image)?;
    let mut eng = engine::Engine::load(model_dir)?;
    let (face, emb) = eng.embed_largest(&img)?;
    print_face(&face);
    let norm = emb
        .vector
        .iter()
        .map(|v| (*v as f64).powi(2))
        .sum::<f64>()
        .sqrt();
    println!("embedding dim: {}", emb.vector.len());
    println!("embedding norm (after L2 normalization): {norm:.6}");
    println!(
        "embedding raw norm (before normalization): {:.6}",
        emb.raw_norm
    );
    println!(
        "embedding first 5: {:?}",
        &emb.vector[..emb.vector.len().min(5)]
    );
    Ok(())
}

fn cmd_compare(model_dir: &Path, a: &Path, b: &Path) -> Result<()> {
    let mut eng = engine::Engine::load(model_dir)?;
    let ia = capture::load_image_rgb(a)?;
    let ib = capture::load_image_rgb(b)?;
    let (_, ea) = eng.embed_largest(&ia)?;
    let (_, eb) = eng.embed_largest(&ib)?;
    println!(
        "cosine similarity: {:.4}",
        align::cosine(&ea.vector, &eb.vector)
    );
    Ok(())
}

fn enroll_embeddings(eng: &mut engine::Engine, dir: &Path) -> Result<Vec<(String, Vec<f32>)>> {
    let mut entries: Vec<PathBuf> = Vec::new();
    let rd = std::fs::read_dir(dir).map_err(|e| error::io_at(dir, e))?;
    for entry in rd {
        let entry = entry?;
        let p = entry.path();
        let ext = p
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        if matches!(ext.as_str(), "png" | "jpg" | "jpeg") {
            entries.push(p);
        }
    }
    entries.sort();
    if entries.is_empty() {
        return Err(SpikeError::Invalid(format!(
            "no .png/.jpg images in enroll dir {}",
            dir.display()
        )));
    }
    let mut out = Vec::new();
    for p in entries {
        let img = capture::load_image_rgb(&p)?;
        match eng.embed_largest(&img) {
            Ok((_, emb)) => out.push((
                p.file_name()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_default(),
                emb.vector,
            )),
            Err(e) => println!("enroll {}: skipped ({e})", p.display()),
        }
    }
    if out.is_empty() {
        return Err(SpikeError::NoFace(
            "no enroll image contained a face".into(),
        ));
    }
    Ok(out)
}

fn cmd_verify_live(model_dir: &Path, enroll_dir: &Path) -> Result<()> {
    let mut eng = engine::Engine::load(model_dir)?;
    let enrolled = enroll_embeddings(&mut eng, enroll_dir)?;
    println!("enrolled templates: {}", enrolled.len());

    let paired = capture::capture_paired()?;
    let ir_rgb = capture::gray_to_rgb(&paired.ir);
    println!(
        "captured: rgb {}x{} brightness {:.2}, ir {}x{} brightness {:.2}",
        paired.rgb.width(),
        paired.rgb.height(),
        capture::mean_brightness_rgb(&paired.rgb),
        paired.ir.width(),
        paired.ir.height(),
        capture::mean_brightness_gray(&paired.ir)
    );

    for (sensor, img) in [("rgb", &paired.rgb), ("ir", &ir_rgb)] {
        match eng.embed_largest(img) {
            Ok((face, emb)) => {
                println!(
                    "{sensor}: face score={:.4} box=({:.0},{:.0},{:.0}x{:.0})",
                    face.score, face.x, face.y, face.w, face.h
                );
                let mut best = f32::MIN;
                for (name, tmpl) in &enrolled {
                    let s = align::cosine(&emb.vector, tmpl);
                    best = best.max(s);
                    println!("  {sensor} vs {name}: cosine {s:.4}");
                }
                println!("  {sensor} best: {best:.4}");
            }
            Err(e) => println!("{sensor}: {e}"),
        }
    }
    Ok(())
}

fn percentile(sorted: &[f64], pct: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let idx = ((pct / 100.0) * sorted.len() as f64).ceil() as usize;
    sorted[idx.saturating_sub(1).min(sorted.len() - 1)]
}

fn peak_rss_kb() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmHWM:") {
            return rest
                .trim()
                .trim_end_matches(" kB")
                .trim()
                .parse::<u64>()
                .ok();
        }
    }
    None
}

fn cmd_bench(model_dir: &Path, image: &Path, iters: usize) -> Result<()> {
    if iters == 0 {
        return Err(SpikeError::Invalid("--iters must be >= 1".into()));
    }
    let img = capture::load_image_rgb(image)?;
    let mut eng = engine::Engine::load(model_dir)?;
    // Warm-up (model load excluded from timings below).
    let faces = eng.detect(&img)?;
    let largest = faces
        .iter()
        .max_by(|a, b| {
            a.area()
                .partial_cmp(&b.area())
                .unwrap_or(std::cmp::Ordering::Equal)
        })
        .cloned();

    let mut detect_ms = Vec::with_capacity(iters);
    for _ in 0..iters {
        let t = Instant::now();
        let _ = eng.detect(&img)?;
        detect_ms.push(t.elapsed().as_secs_f64() * 1000.0);
    }
    detect_ms.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let mean = detect_ms.iter().sum::<f64>() / detect_ms.len() as f64;
    println!(
        "detect:      n={} mean={:.2} ms p95={:.2} ms",
        iters,
        mean,
        percentile(&detect_ms, 95.0)
    );

    match largest {
        Some(face) => {
            let mut embed_ms = Vec::with_capacity(iters);
            for _ in 0..iters {
                let t = Instant::now();
                let _ = eng.embed_face(&img, &face)?;
                embed_ms.push(t.elapsed().as_secs_f64() * 1000.0);
            }
            embed_ms.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
            let mean = embed_ms.iter().sum::<f64>() / embed_ms.len() as f64;
            println!(
                "align+embed: n={} mean={:.2} ms p95={:.2} ms",
                iters,
                mean,
                percentile(&embed_ms, 95.0)
            );
        }
        None => println!("align+embed: n/a (no face in image)"),
    }
    match peak_rss_kb() {
        Some(kb) => println!("peak RSS (VmHWM): {kb} kB ({:.1} MiB)", kb as f64 / 1024.0),
        None => println!("peak RSS (VmHWM): unavailable"),
    }
    Ok(())
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    match &cli.command {
        Command::Capture { out_dir } => cmd_capture(out_dir),
        Command::Detect { image } => cmd_detect(&cli.model_dir, image),
        Command::Embed { image } => cmd_embed(&cli.model_dir, image),
        Command::Compare { a, b } => cmd_compare(&cli.model_dir, a, b),
        Command::VerifyLive { enroll_dir } => cmd_verify_live(&cli.model_dir, enroll_dir),
        Command::Bench { image, iters } => cmd_bench(&cli.model_dir, image, *iters),
    }
}

fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}
