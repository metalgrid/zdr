mod align;
mod args;
mod camfind;
mod config;
mod capture;
mod consent;
mod engine;
mod enroll;
mod error;
mod feedback;
mod service;
mod templates;
mod verify;
mod yunet;

use args::Args;
use clap::Parser;
use engine::OnnxEngine;
use service::Authenticator;
use std::sync::Arc;
use verify::FaceVerifier;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    // Config file: missing is fine, present-but-invalid is fatal.
    let file_config = config::load_file(&args.config)
        .map_err(|e| Box::<dyn std::error::Error>::from(e))?
        .unwrap_or_default();
    let detected = if config::ResolvedConfig::needs_detection(&args, &file_config) {
        camfind::detect()
    } else {
        camfind::DetectedCameras::default()
    };
    for line in &detected.summary {
        eprintln!("zdrd: camfind: {line}");
    }
    let cfg = config::ResolvedConfig::resolve(&args, &file_config, &detected);
    let show = |p: &Option<std::path::PathBuf>| match p {
        Some(p) => p.display().to_string(),
        None => "(none detected)".to_string(),
    };
    eprintln!("zdrd: resolved configuration:");
    eprintln!("zdrd:   rgb-camera: {}", show(&cfg.rgb_camera));
    eprintln!("zdrd:   ir-camera: {}", show(&cfg.ir_camera));
    eprintln!("zdrd:   require-ir: {}", cfg.require_ir);
    eprintln!("zdrd:   threshold: {}", cfg.threshold);
    eprintln!("zdrd:   auth-dir: {}", cfg.auth_dir.display());
    eprintln!("zdrd:   yunet: {}", cfg.yunet.display());
    eprintln!("zdrd:   sface: {}", cfg.sface.display());
    if !cfg.require_ir {
        eprintln!("zdrd: WARNING: RGB-only mode (require_ir=false)");
        eprintln!("zdrd: WARNING: a printed photo or a photo on a phone screen can pass this check");
        eprintln!("zdrd: WARNING: this mode is convenience only, not secure authentication");
    }

    // Models stay loaded for the daemon's lifetime. A model load failure
    // is fatal at startup (fail closed, no half-working daemon).
    let engine = OnnxEngine::load(&cfg.yunet, &cfg.sface)
        .map_err(|e| Box::<dyn std::error::Error>::from(e))?;
    let verifier = FaceVerifier::new(
        engine,
        cfg.auth_dir.clone(),
        cfg.rgb_camera
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_default(),
        cfg.ir_camera
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_default(),
        cfg.threshold,
    );
    let svc = Authenticator::new(Arc::new(verifier));
    let _conn = zbus::connection::Builder::system()?
        .name("org.zdr.Authenticator")?
        .serve_at("/org/zdr/Authenticator", svc)?
        .build()
        .await?;
    eprintln!("zdrd: listening on system bus as org.zdr.Authenticator");

    shutdown_signal().await;
    eprintln!("zdrd: shutting down");
    Ok(())
}

/// Resolve on SIGINT or SIGTERM so systemd stops are graceful.
async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(e) = tokio::signal::ctrl_c().await {
            eprintln!("zdrd: ctrl-c handler failed: {e}");
        }
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut sig) => {
                sig.recv().await;
            }
            Err(e) => eprintln!("zdrd: SIGTERM handler failed: {e}"),
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}
