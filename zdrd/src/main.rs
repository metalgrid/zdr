mod args;
mod consent;
mod service;

use args::Args;
use clap::Parser;
use service::{Authenticator, UnavailableVerifier};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    eprintln!(
        "zdrd: starting (rgb={}, ir={}, auth-dir={}, threshold={})",
        args.rgb_camera,
        args.ir_camera,
        args.auth_dir.display(),
        args.threshold
    );

    let svc = Authenticator::new(Arc::new(UnavailableVerifier));
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
