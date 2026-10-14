//! `zdr-agent`: per-session agent for zdr face authentication.
//!
//! Connects to the system bus, registers with the `org.zdr.Authenticator`
//! daemon, and for each `AuthRequested` signal addressed to this user
//! shows a single `zenity` confirmation popup. The user's decision is
//! returned to the daemon with `Respond`. See `README.md` for the
//! fail-closed rules this binary follows.

use std::io;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use zbus::blocking::Connection;
use zdr_agent::{
    approved_for_exit_code, build_popup_text, is_request_for_user, own_uid, own_username,
    zenity_args, SeenRequests,
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

/// Show the zenity popup for one request and return the decision.
///
/// Fail-closed: a missing `zenity`, a spawn failure, a timeout
/// (exit 5), dismissal (exit 1), or any other non-zero outcome all
/// deny. The label reaches zenity only as part of the single
/// `--text` argument built by [`zenity_args`]; no shell is involved.
fn prompt_user(service: &str, user: &str, tty: &str, label: &str) -> bool {
    let text = build_popup_text(service, user, tty, label);
    let args = zenity_args(&text);
    match Command::new("zenity")
        .args(&args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .status()
    {
        Ok(status) => {
            // ExitStatus::code() is None if zenity was killed by a
            // signal; map that to -1, which denies.
            let code = status.code().unwrap_or(-1);
            let approved = approved_for_exit_code(code);
            eprintln!("zdr-agent: zenity exited {code}; approving={approved}");
            approved
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            eprintln!("zdr-agent: zenity not found in PATH; denying (fail closed)");
            false
        }
        Err(e) => {
            eprintln!("zdr-agent: failed to run zenity: {e}; denying (fail closed)");
            false
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
