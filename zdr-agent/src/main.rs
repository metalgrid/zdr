//! `zdr-agent`: per-session agent for zdr face authentication.
//!
//! Connects to the system bus, registers with the `org.zdr.Authenticator`
//! daemon, and for each `AuthRequested` signal addressed to this user
//! shows a single confirmation prompt via the first available prompt
//! backend (custom command, QtQuick host, `qml6`, desktop
//! notification). The user's decision is returned to the daemon with
//! `Respond`. See `README.md` for the backend chain and the
//! fail-closed rules this binary follows.

mod notify;

use std::io;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use zbus::blocking::Connection;
use zdr_agent::{
    approved_for_exit_code, choose_backend, custom_invocation, find_in_path, host_invocation,
    is_request_for_user, own_uid, own_username, parse_prompt_mode, prompt_host_candidates,
    prompt_qml_candidates, qml6_invocation, resolve_first_existing, PromptBackend, PromptInvocation,
    PromptMode, SeenRequests, PROMPT_PROBE_TIMEOUT, PROMPT_WAIT_TIMEOUT,
};

// ---------------------------------------------------------------------------
// D-Bus proxy for the frozen wire contract:
//   bus name   org.zdr.Authenticator
//   path       /org/zdr/Authenticator
//   interface  org.zdr.Authenticator
//   RegisterAgent() -> ()
//   signal AuthRequested(request_id:s, user:s, service:s, tty:s, label:s)
//   Respond(request_id:s, approved:b) -> ()
// The daemon records this connection's unique name and uid at
// RegisterAgent time and rejects Respond from any other connection,
// so registration and responses always go over the same connection.
// ---------------------------------------------------------------------------
#[zbus::proxy(
    interface = "org.zdr.Authenticator",
    default_service = "org.zdr.Authenticator",
    default_path = "/org/zdr/Authenticator"
)]
trait Authenticator {
    fn register_agent(&self) -> zbus::Result<()>;
    fn respond(&self, request_id: &str, approved: bool) -> zbus::Result<()>;

    #[zbus(signal)]
    fn auth_requested(
        &self,
        request_id: &str,
        user: &str,
        service: &str,
        tty: &str,
        label: &str,
    ) -> zbus::Result<()>;
}

/// Set by the SIGTERM/SIGINT handler; polled by every blocking loop.
static SHUTDOWN: AtomicBool = AtomicBool::new(false);

extern "C" fn on_shutdown_signal(_sig: libc::c_int) {
    SHUTDOWN.store(true, Ordering::SeqCst);
}

/// Install SIGTERM/SIGINT handlers that only set [`SHUTDOWN`].
///
/// Installed *without* `SA_RESTART`, so a signal also interrupts the
/// blocking D-Bus read; the session loop then notices the flag and
/// exits instead of reconnecting.
fn install_signal_handlers() -> io::Result<()> {
    // SAFETY: sigemptyset/sigaction are async-signal-safe to call
    // here; the handler itself only stores to an AtomicBool, which
    // is lock-free and async-signal-safe. sa is zeroed before use,
    // which clears sa_mask/sa_flags and any restorer field.
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = on_shutdown_signal as extern "C" fn(libc::c_int) as usize;
        if libc::sigemptyset(&mut sa.sa_mask) != 0 {
            return Err(io::Error::last_os_error());
        }
        sa.sa_flags = 0; // no SA_RESTART: interrupt blocking syscalls
        for sig in [libc::SIGTERM, libc::SIGINT] {
            if libc::sigaction(sig, &sa, std::ptr::null_mut()) != 0 {
                return Err(io::Error::last_os_error());
            }
        }
    }
    Ok(())
}

fn shutdown_requested() -> bool {
    SHUTDOWN.load(Ordering::SeqCst)
}

/// Sleep for `dur`, waking early (in small slices) if shutdown is
/// requested. Returns `true` if the full duration elapsed.
fn sleep_unless_shutdown(dur: Duration) -> bool {
    let step = Duration::from_millis(50);
    let mut elapsed = Duration::ZERO;
    while elapsed < dur {
        if shutdown_requested() {
            return false;
        }
        let nap = step.min(dur - elapsed);
        std::thread::sleep(nap);
        elapsed += nap;
    }
    !shutdown_requested()
}

fn env_nonempty(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.trim().is_empty())
}

/// Wait for a prompt child with a hard timeout. Returns the exit
/// code (`-1` if killed / no code), or `None` on a wait error.
/// The child is killed when the timeout elapses or shutdown is
/// requested.
fn wait_child(child: &mut Child, timeout: Duration, what: &str) -> Option<i32> {
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Some(status.code().unwrap_or(-1)),
            Ok(None) => {
                if shutdown_requested() || started.elapsed() >= timeout {
                    if started.elapsed() >= timeout {
                        eprintln!("zdr-agent: {what} exceeded {timeout:?}; killing it");
                    }
                    let _ = child.kill();
                    let _ = child.wait();
                    return Some(-1);
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => {
                eprintln!("zdr-agent: waiting for {what} failed: {e}");
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }
}

/// Run one prompt invocation. `Some(decision)` means the front-end
/// actually ran (any exit code, timeout, or kill is a decision to
/// deny unless it exited 0); `None` means it failed to run at all,
/// so the backend chain may fall through to the next backend.
fn run_invocation(inv: &PromptInvocation, what: &str) -> Option<bool> {
    let mut child = match Command::new(&inv.program)
        .args(&inv.args)
        // The QML front-end reads theme files via file:// XHR,
        // which Qt only allows with this opt-in. Harmless for
        // other front-ends.
        .env("QML_XHR_ALLOW_FILE_READ", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .spawn()
    {
        Ok(child) => child,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            eprintln!("zdr-agent: {what} not found ({}); backend unavailable", inv.program.display());
            return None;
        }
        Err(e) => {
            eprintln!("zdr-agent: failed to run {what} ({}): {e}; backend unavailable", inv.program.display());
            return None;
        }
    };
    let code = wait_child(&mut child, PROMPT_WAIT_TIMEOUT, what)?;
    let approved = approved_for_exit_code(code);
    eprintln!("zdr-agent: {what} exited {code}; approving={approved}");
    Some(approved)
}

/// Probe a `zdr-prompt` host candidate with `--probe` (3 s cap):
/// exit 0 means its Qt libraries loaded and a QGuiApplication
/// initialised, so the real prompt is worth trying.
fn probe_prompt_bin(program: &Path) -> bool {
    let mut child = match Command::new(program)
        .arg("--probe")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(child) => child,
        Err(e) => {
            eprintln!("zdr-agent: Qt host probe could not run {}: {e}", program.display());
            return false;
        }
    };
    match wait_child(&mut child, PROMPT_PROBE_TIMEOUT, "Qt host probe") {
        Some(0) => true,
        other => {
            eprintln!("zdr-agent: Qt host probe for {} failed (exit {other:?})", program.display());
            false
        }
    }
}

fn resolve_qml_path() -> Option<PathBuf> {
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(Path::to_path_buf));
    let candidates = prompt_qml_candidates(
        env_nonempty("ZDR_PROMPT_QML").as_deref(),
        &cwd,
        exe_dir.as_deref(),
    );
    let resolved = resolve_first_existing(&candidates);
    if resolved.is_none() {
        eprintln!("zdr-agent: no zdr-prompt.qml found in {candidates:?}");
    }
    resolved
}

/// Show the prompt for one request via the backend chain and
/// return the decision. Fail-closed throughout: only an explicit
/// approval from a front-end that actually ran approves.
///
/// Chain (per request; `ZDR_PROMPT=qt|qml|notify|none` forces or
/// disables front-ends instead): custom `ZDR_PROMPT_CMD`, Qt host
/// (`ZDR_PROMPT_BIN` / `/usr/lib/zdr/zdr-prompt` / PATH, gated by
/// a `--probe`), `qml6` with the resolved QML file, desktop
/// notification, deny. An executable that fails to *run* falls
/// through to the next backend; one that ran and exited non-zero
/// (or timed out) has answered: deny.
fn prompt_user(service: &str, user: &str, tty: &str, label: &str) -> bool {
    let started = Instant::now();
    let mode = parse_prompt_mode(env_nonempty("ZDR_PROMPT").as_deref());
    if mode != PromptMode::Auto {
        eprintln!("zdr-agent: prompt mode forced by ZDR_PROMPT: {mode:?}");
    }

    // Backend facts established up front (cheap checks only; the
    // Qt host is probed lazily when its turn comes).
    let custom_program: Option<PathBuf> = match env_nonempty("ZDR_PROMPT_CMD") {
        Some(cmd) if Path::new(&cmd).is_absolute() => Some(PathBuf::from(cmd)),
        Some(cmd) => {
            eprintln!("zdr-agent: custom backend skipped: ZDR_PROMPT_CMD={cmd:?} is not an absolute path");
            None
        }
        None => None,
    };
    let qml_path = resolve_qml_path();
    let path_env = std::env::var("PATH").ok();
    let qml6_program: Option<PathBuf> = match env_nonempty("ZDR_QML_BIN") {
        Some(b) => find_in_path(&b, path_env.as_deref()).or_else(|| PathBuf::from(&b).is_file().then(|| PathBuf::from(&b))),
        None => find_in_path("qml6", path_env.as_deref()),
    };
    let mut custom_available = custom_program.is_some();
    let mut host_available = true; // until a probe rules it out
    let mut qml_available = qml6_program.is_some() && qml_path.is_some();
    if qml6_program.is_none() {
        eprintln!("zdr-agent: qml6 backend skipped: qml6 not on PATH");
    } else if qml_path.is_none() {
        eprintln!("zdr-agent: qml6 backend skipped: QML file not found");
    }

    loop {
        match choose_backend(mode, custom_available, host_available, qml_available) {
            PromptBackend::Custom => {
                let program = custom_program.clone().expect("custom checked available");
                eprintln!("zdr-agent: prompt backend: custom command {}", program.display());
                let inv = custom_invocation(&program, service, user, tty, label);
                match run_invocation(&inv, "custom prompt") {
                    Some(decision) => return decision,
                    None => {
                        eprintln!("zdr-agent: custom prompt failed to run; falling through");
                        custom_available = false;
                    }
                }
            }
            PromptBackend::QtHost => {
                let Some(qml) = qml_path.clone() else {
                    eprintln!("zdr-agent: Qt host backend skipped: QML file not found");
                    host_available = false;
                    continue;
                };
                let candidates = prompt_host_candidates(
                    env_nonempty("ZDR_PROMPT_BIN").as_deref(),
                    path_env.as_deref(),
                );
                let probed = candidates
                    .iter()
                    .filter(|candidate| candidate.is_file())
                    .find(|candidate| probe_prompt_bin(candidate))
                    .cloned();
                let Some(program) = probed else {
                    eprintln!("zdr-agent: Qt host backend skipped: no candidate passed --probe ({candidates:?})");
                    host_available = false;
                    continue;
                };
                eprintln!("zdr-agent: prompt backend: Qt host {}", program.display());
                let inv = host_invocation(&program, &qml, service, user, tty, label);
                match run_invocation(&inv, "Qt prompt host") {
                    Some(decision) => return decision,
                    None => {
                        eprintln!("zdr-agent: Qt prompt host failed to run; falling through");
                        host_available = false;
                    }
                }
            }
            PromptBackend::Qml6 => {
                let (program, qml) = (qml6_program.clone().expect("qml6 checked available"), qml_path.clone().expect("qml checked available"));
                eprintln!("zdr-agent: prompt backend: qml6 {}", qml.display());
                let inv = qml6_invocation(&program, &qml, service, user, tty, label);
                match run_invocation(&inv, "qml6 prompt") {
                    Some(decision) => return decision,
                    None => {
                        eprintln!("zdr-agent: qml6 prompt failed to run; falling through");
                        qml_available = false;
                    }
                }
            }
            PromptBackend::Notify => {
                eprintln!("zdr-agent: prompt backend: desktop notification");
                let budget = PROMPT_WAIT_TIMEOUT.saturating_sub(started.elapsed());
                return notify::prompt_via_notification(service, user, tty, label, budget);
            }
            PromptBackend::None => {
                eprintln!("zdr-agent: no prompt backend available; denying (fail closed)");
                return false;
            }
        }
    }
}

/// One bus session: connect, subscribe, register, serve until the
/// connection drops, shutdown is requested, or an error forces a
/// reconnect. Errors are returned so the caller can log and retry.
fn run_session(own_username: &str) -> zbus::Result<()> {
    let connection = Connection::system()?;
    let proxy = AuthenticatorProxyBlocking::new(&connection)?;

    // Subscribe *before* RegisterAgent so a request emitted as soon
    // as the daemon notices us cannot be missed.
    let mut signals = proxy.receive_auth_requested()?;

    proxy.register_agent()?;
    eprintln!(
        "zdr-agent: registered with org.zdr.Authenticator as {} (uid {}, user {})",
        connection
            .unique_name()
            .map(|n| n.to_string())
            .unwrap_or_else(|| "<unknown>".to_string()),
        own_uid(),
        own_username,
    );

    let mut seen = SeenRequests::new();

    // Signals are handled one at a time, synchronously: the next
    // popup can only appear after the current one is answered, so
    // two popups never overlap. Further requests wait in the D-Bus
    // signal stream until we get to them.
    for signal in signals.by_ref() {
        if shutdown_requested() {
            break;
        }
        let args = match signal.args() {
            Ok(args) => args,
            Err(e) => {
                eprintln!("zdr-agent: ignoring malformed AuthRequested signal: {e}");
                continue;
            }
        };
        let (request_id, user, service, tty, label) = (
            args.request_id(),
            args.user(),
            args.service(),
            args.tty(),
            args.label(),
        );

        if !is_request_for_user(user, own_username) {
            eprintln!(
                "zdr-agent: ignoring AuthRequested {request_id} for other user {user:?}"
            );
            continue;
        }
        if !seen.mark_seen(request_id) {
            eprintln!("zdr-agent: dropping duplicate AuthRequested {request_id}");
            continue;
        }

        eprintln!(
            "zdr-agent: AuthRequested {request_id} service={service:?} tty={tty:?}; showing popup"
        );
        let approved = prompt_user(service, user, tty, label);

        if shutdown_requested() {
            eprintln!("zdr-agent: shutting down; not responding to {request_id}");
            break;
        }
        // Must go over this same connection: the daemon recorded
        // our unique name/uid at RegisterAgent and rejects Respond
        // from any other connection.
        if let Err(e) = proxy.respond(request_id, approved) {
            eprintln!("zdr-agent: Respond({request_id}, {approved}) failed: {e}");
            return Err(e);
        }
        eprintln!("zdr-agent: responded to {request_id}: approved={approved}");
    }

    if shutdown_requested() {
        eprintln!("zdr-agent: session ended (shutdown requested)");
        Ok(())
    } else {
        // Iterator ended without an error surfaced to us: treat as
        // a dropped connection so the caller reconnects.
        Err(zbus::Error::Failure(
            "AuthRequested signal stream ended".to_string(),
        ))
    }
}

fn main() {
    if let Err(e) = install_signal_handlers() {
        eprintln!("zdr-agent: failed to install signal handlers: {e}");
        std::process::exit(1);
    }

    // Our identity comes from getuid/getpwuid, never from $USER:
    // the request filter is only meaningful against the passwd
    // entry for the uid this process actually runs as.
    let username = match own_username() {
        Some(name) => name,
        None => {
            eprintln!(
                "zdr-agent: cannot resolve username for uid {}; exiting",
                own_uid()
            );
            std::process::exit(1);
        }
    };
    eprintln!(
        "zdr-agent: starting as user {username} (uid {}); connecting to system bus",
        own_uid()
    );

    // Reconnect loop: if the bus connection drops or RegisterAgent
    // fails (daemon down), retry every 2 s forever.
    loop {
        if shutdown_requested() {
            break;
        }
        match run_session(&username) {
            Ok(()) => break, // shutdown requested inside the session
            Err(e) => {
                if shutdown_requested() {
                    break;
                }
                eprintln!(
                    "zdr-agent: session failed: {e}; retrying RegisterAgent in 2s"
                );
            }
        }
        if !sleep_unless_shutdown(Duration::from_secs(2)) {
            break;
        }
    }

    eprintln!("zdr-agent: exiting cleanly");
}
