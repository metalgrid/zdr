extern crate pam;

use std::ffi::{CStr, CString};
use std::sync::mpsc;
use std::time::Duration;

use pam::constants::{PamFlag, PamResultCode, PAM_PROMPT_ECHO_ON, PAM_TEXT_INFO};
use pam::conv::Conv;
use pam::items::{AuthTok, RHost, Service, Tty, User};
use pam::module::{PamHandle, PamHooks};
use zbus::blocking::Connection;

/// D-Bus wait bounds. `zbus` 4.1.1 (blocking) has no per-call reply timeout —
/// its calls can wait for a reply indefinitely — so every call below runs on
/// a worker thread and the PAM thread only waits with `recv_timeout`. Total
/// worst-case D-Bus wait inside `pam_sm_authenticate`:
///
/// * agent channel:    5 s BeginAuth + 35 s AwaitConsent + 15 s CaptureVerify
///   (or CaptureVerifyAuthtok in mode=authtok, same ceiling; it replaces,
///   not adds to, CaptureVerify) (+ 2 s Cancel on an error path) ≈ 57 s
/// * terminal channel: 5 s BeginAuth + 5 s Respond + 15 s CaptureVerify
///   (+ 2 s Cancel on an error path) ≈ 27 s
///
/// The PAM conversation (the user typing at the terminal prompt) is not
/// counted: like a password prompt, it is paced by the user/application, not
/// by this module. On timeout the detached worker may stay blocked inside
/// zbus until the daemon or bus answers or the process exits; the PAM-facing
/// wait above is bounded regardless.
const BEGIN_AUTH_TIMEOUT: Duration = Duration::from_secs(5);
const RESPOND_TIMEOUT: Duration = Duration::from_secs(5);
const AWAIT_CONSENT_TIMEOUT: Duration = Duration::from_secs(35);
const CAPTURE_VERIFY_TIMEOUT: Duration = Duration::from_secs(15);
const CANCEL_TIMEOUT: Duration = Duration::from_secs(2);

/// Log a failure reason to stderr and return PAM_AUTH_ERR. The module must
/// never fail silently: under pamtester/sudo this lands on the terminal, and
/// under a display manager it lands in the journal via the service.
fn fail(context: &str, error: &str) -> PamResultCode {
    eprintln!("pam_zdr: {context}: {error}");
    PamResultCode::PAM_AUTH_ERR
}

struct PamZdr;
pam::pam_hooks!(PamZdr);

impl PamHooks for PamZdr {
    // This function performs the task of authenticating the user.
    fn sm_authenticate(pamh: &mut PamHandle, args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        // Parse module arguments before anything else. An unknown `mode=`
        // value fails closed: guessing a mode could authenticate (decide)
        // when the administrator asked for token hand-off (authtok), or
        // vice versa.
        let mode = match parse_mode(&args) {
            Ok(mode) => mode,
            Err(value) => return fail("module arguments", &format!("unknown mode {value:?}")),
        };
        let quiet = parse_quiet(&args);

        // Do NOT use PamHandle::get_user from pam-bindings 0.1.1: it passes
        // an immutable local's address to pam_get_user, which is UB. In
        // release builds the optimizer folds the null check, get_user then
        // returns Err(PAM_SUCCESS), and pam_try! turned that into instant
        // PAM_SUCCESS with no authentication at all. get_item uses a
        // correctly mutable pointer.
        let user = match pamh.get_item::<User>() {
            Ok(Some(user)) => user.0.to_string_lossy().into_owned(),
            Ok(None) => return fail("reading PAM_USER", "item not set"),
            Err(code) => return fail("reading PAM_USER", &format!("{code:?}")),
        };

        // Remote sessions never trigger face auth (acceptance test 12): if
        // PAM_RHOST is set and non-empty, fail at once, printing nothing, so
        // the password module next in the stack handles the attempt. If the
        // item cannot even be read, we cannot rule out a remote session, so
        // fail closed the same way.
        let remote = match pamh.get_item::<RHost>() {
            Ok(Some(host)) => !host.0.to_bytes().is_empty(),
            Ok(None) => false,
            Err(code) => return fail("reading PAM_RHOST", &format!("{code:?}")),
        };
        if remote {
            return PamResultCode::PAM_AUTH_ERR;
        }

        let service = match pamh.get_item::<Service>() {
            Ok(Some(service)) => service.0.to_string_lossy().into_owned(),
            _ => String::new(),
        };
        let tty = match pamh.get_item::<Tty>() {
            Ok(Some(tty)) => tty.0.to_string_lossy().into_owned(),
            _ => String::new(),
        };
        let label = current_label();

        // Fail closed when the daemon is unreachable or too slow: PAM_AUTH_ERR
        // lets the password fallback run.
        let (connection, request_id, channel) = match call_begin_auth(user, service, tty, label) {
            Ok(parts) => parts,
            Err(e) => return fail("BeginAuth", &e),
        };
        // From here on BeginAuth has succeeded: any error path cancels the
        // request best-effort before returning.

        match channel.as_str() {
            "agent" => {
                // Best-effort hint; the GUI popup is the real prompt. A
                // missing/failing conversation must not block approval.
                // With `quiet`, send nothing: some agents (Noctalia's
                // polkit panel) open a system modal on the first
                // conversation message, covering our consent popup.
                // Silence keeps the popup the only surface; the agent
                // still appears later if a password is needed.
                if !quiet {
                    if let Ok(Some(conv)) = pamh.get_item::<Conv>() {
                        let _ = conv.send(
                            PAM_TEXT_INFO,
                            "Face authentication: approve in the popup\u{2026}",
                        );
                    }
                }
                match call_await_consent(&connection, &request_id) {
                    Ok(outcome) => match parse_outcome(&outcome) {
                        Some(consent) => finish(pamh, mode, &connection, &request_id, consent),
                        None => {
                            cancel_best_effort(&connection, &request_id);
                            fail("AwaitConsent", "unknown outcome string")
                        }
                    },
                    Err(e) => {
                        cancel_best_effort(&connection, &request_id);
                        fail("AwaitConsent", &e)
                    }
                }
            }
            "terminal" => {
                let answer = prompt_terminal(pamh);
                let yes = match answer.as_deref() {
                    Some(text) => parse_yes(text),
                    None => false,
                };
                if !yes {
                    // Empty input, EOF, conversation error, or an explicit
                    // "no" all mean no. Tell the daemon (best-effort) and
                    // fail so the password prompt follows. No capture may
                    // happen without a yes.
                    if let Err(e) = call_respond(&connection, &request_id, false) {
                        eprintln!("pam_zdr: Respond(false): {e}");
                        cancel_best_effort(&connection, &request_id);
                    }
                    return PamResultCode::PAM_AUTH_ERR;
                }
                if let Err(e) = call_respond(&connection, &request_id, true) {
                    cancel_best_effort(&connection, &request_id);
                    return fail("Respond(true)", &e);
                }
                // The daemon records Respond(true) as approval; capturing is
                // the next and only remaining step.
                finish(pamh, mode, &connection, &request_id, Consent::Approved)
            }
            other => {
                cancel_best_effort(&connection, &request_id);
                fail(
                    "BeginAuth channel",
                    &format!("unexpected channel {other:?}"),
                )
            }
        }
    }

    fn sm_setcred(_pamh: &mut PamHandle, _args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        PamResultCode::PAM_SUCCESS
    }

    fn acct_mgmt(_pamh: &mut PamHandle, _args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        PamResultCode::PAM_SUCCESS
    }
}

/// Ask the terminal consent question through the PAM conversation. Returns
/// `None` for a missing conversation, a conversation error, or EOF — the
/// caller treats all of these as "no".
fn prompt_terminal(pamh: &mut PamHandle) -> Option<String> {
    let conv = pamh.get_item::<Conv>().ok().flatten()?;
    match conv.send(PAM_PROMPT_ECHO_ON, "Use face recognition? [y/N] ") {
        Ok(Some(response)) => Some(response.to_string_lossy().into_owned()),
        Ok(None) | Err(_) => None,
    }
}

/// Map the frozen `AwaitConsent` outcome string to [`Consent`]. Unknown
/// outcomes return `None` so the caller can fail (and cancel) instead of
/// guessing.
fn parse_outcome(outcome: &str) -> Option<Consent> {
    match outcome {
        "approved" => Some(Consent::Approved),
        "denied" => Some(Consent::Denied),
        "expired" => Some(Consent::Expired),
        _ => None,
    }
}

/// Shared tail of both consent channels: only an approved request reaches
/// `CaptureVerify`; success requires it to report a match.
fn finish(
    pamh: &mut PamHandle,
    mode: Mode,
    connection: &Connection,
    request_id: &str,
    consent: Consent,
) -> PamResultCode {
    if !matches!(consent, Consent::Approved) {
        return decide_mode(mode, &consent, None, false, false);
    }
    match mode {
        Mode::Decide => finish_decide(connection, request_id, &consent),
        Mode::Authtok => finish_authtok(pamh, connection, request_id, &consent),
    }
}

/// Decide-mode tail: `CaptureVerify`; a match alone authenticates.
fn finish_decide(connection: &Connection, request_id: &str, consent: &Consent) -> PamResultCode {
    match call_capture_verify(connection, request_id) {
        Ok((matched, reason)) => {
            eprintln!("pam_zdr: CaptureVerify matched={matched} reason={reason}");
            decide_mode(Mode::Decide, consent, Some(matched), false, false)
        }
        Err(e) => {
            eprintln!("pam_zdr: CaptureVerify: {e}");
            cancel_best_effort(connection, request_id);
            decide_mode(Mode::Decide, consent, None, false, false)
        }
    }
}

/// Authtok-mode tail: `CaptureVerifyAuthtok`; a match never authenticates
/// by itself. On a match with a sealed password, deposit it as
/// `PAM_AUTHTOK` and return `PAM_IGNORE` so `pam_unix` (`try_first_pass`)
/// validates it and downstream modules consume it as in a password login.
/// On a match with no sealed password, return `PAM_IGNORE` with no token
/// set so the stack prompts normally. The password itself is never logged.
fn finish_authtok(
    pamh: &mut PamHandle,
    connection: &Connection,
    request_id: &str,
    consent: &Consent,
) -> PamResultCode {
    match call_capture_verify_authtok(connection, request_id) {
        Ok((matched, reason, mut password)) => {
            eprintln!("pam_zdr: CaptureVerifyAuthtok matched={matched} reason={reason}");
            let token_present = !password.is_empty();
            let token_set_ok = if matched && token_present {
                let ok = set_authtok(pamh, &password);
                if ok {
                    eprintln!("pam_zdr: token set for pam_unix");
                } else {
                    eprintln!("pam_zdr: token set for pam_unix failed");
                }
                ok
            } else {
                false
            };
            wipe(&mut password);
            decide_mode(
                Mode::Authtok,
                consent,
                Some(matched),
                token_present,
                token_set_ok,
            )
        }
        Err(e) => {
            eprintln!("pam_zdr: CaptureVerifyAuthtok: {e}");
            cancel_best_effort(connection, request_id);
            decide_mode(Mode::Authtok, consent, None, false, false)
        }
    }
}

/// Zero a buffer in place. Hand-rolled (no new crates); `black_box` keeps
/// the optimizer from eliding writes to a buffer that is about to drop.
fn wipe(buf: &mut [u8]) {
    for byte in buf.iter_mut() {
        *byte = 0;
    }
    let _ = std::hint::black_box(buf);
}

/// Store `password` as the handle's `PAM_AUTHTOK` item. Returns success.
///
/// No direct `pam_set_item` FFI and no new dependency are needed:
/// pam-bindings 0.1.1 does expose setting string items via
/// `PamHandle::set_item_str`, generic over `pam::items::Item`, and
/// `items::AuthTok` (item type 6) is a `CStr` item whose `into_raw` yields
/// exactly the `const char *` `pam_set_item` expects. (The crate does not
/// re-export its `libc`, so this also avoids adding `libc` just for FFI.)
///
/// Lifetime evidence: `pam_set_item(3)` (Linux-PAM manual) states "For this
/// a copy of the object pointed to by the item argument is created", so
/// PAM owns its copy once the call returns and our `CString` may be wiped
/// and dropped immediately afterwards. A password containing an interior
/// NUL cannot be a C string token: `CString::new` fails and we report
/// failure (the caller fails closed) instead of truncating it.
fn set_authtok(pamh: &mut PamHandle, password: &[u8]) -> bool {
    let owned = match CString::new(password) {
        Ok(cstring) => cstring,
        Err(_) => return false,
    };
    let result = pamh.set_item_str(AuthTok(owned.as_c_str()));
    // Recover the CString's buffer and wipe our copy; PAM has its own.
    let mut bytes = owned.into_bytes();
    wipe(&mut bytes);
    result.is_ok()
}

/// Run `call` on a worker thread and wait at most `timeout` for its result.
///
/// This is the bound that zbus 4.1.1's blocking API does not provide (see the
/// timeout constants at the top of this file). Never panics: a spawn failure,
/// a dropped sender, and a timeout all become plain `Err`s.
fn timed_call<T, F>(timeout: Duration, call: F) -> Result<T, String>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, String> + Send + 'static,
{
    let (sender, receiver) = mpsc::channel();
    let spawned = std::thread::Builder::new()
        .name("pam-zdr-dbus".to_string())
        .spawn(move || {
            let _ = sender.send(call());
        });
    if let Err(error) = spawned {
        return Err(format!("could not spawn D-Bus worker: {error}"));
    }
    match receiver.recv_timeout(timeout) {
        Ok(result) => result,
        Err(mpsc::RecvTimeoutError::Timeout) => {
            Err(format!("D-Bus call timed out after {timeout:?}"))
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            Err("D-Bus worker stopped without answering".to_string())
        }
    }
}

/// `BeginAuth(user, service, tty, label) -> (request_id, channel)`. Also
/// establishes the system-bus connection (inside the same timeout budget) and
/// returns it so later calls can reuse it.
fn call_begin_auth(
    user: String,
    service: String,
    tty: String,
    label: String,
) -> Result<(Connection, String, String), String> {
    timed_call(BEGIN_AUTH_TIMEOUT, move || {
        let connection = Connection::system().map_err(|e| e.to_string())?;
        let proxy = ZdrAuthenticatorProxyBlocking::new(&connection).map_err(|e| e.to_string())?;
        let (request_id, channel) = proxy
            .begin_auth(&user, &service, &tty, &label)
            .map_err(|e| e.to_string())?;
        Ok((connection, request_id, channel))
    })
}

/// `Respond(request_id, approved) -> ()`. On the terminal path PAM itself is
/// the responder (uid 0); on the agent path the daemon only accepts the
/// registered agent connection.
fn call_respond(connection: &Connection, request_id: &str, approved: bool) -> Result<(), String> {
    let connection = connection.clone();
    let request_id = request_id.to_string();
    timed_call(RESPOND_TIMEOUT, move || {
        let proxy = ZdrAuthenticatorProxyBlocking::new(&connection).map_err(|e| e.to_string())?;
        proxy
            .respond(&request_id, approved)
            .map_err(|e| e.to_string())
    })
}

/// `AwaitConsent(request_id) -> outcome`, 35 s ceiling (the daemon expires
/// requests sooner; this only guards against a stuck daemon).
fn call_await_consent(connection: &Connection, request_id: &str) -> Result<String, String> {
    let connection = connection.clone();
    let request_id = request_id.to_string();
    timed_call(AWAIT_CONSENT_TIMEOUT, move || {
        let proxy = ZdrAuthenticatorProxyBlocking::new(&connection).map_err(|e| e.to_string())?;
        proxy.await_consent(&request_id).map_err(|e| e.to_string())
    })
}

/// `CaptureVerify(request_id) -> (matched, reason)`. One shot; only ever
/// called after explicit approval, so no camera opens before consent.
fn call_capture_verify(
    connection: &Connection,
    request_id: &str,
) -> Result<(bool, String), String> {
    let connection = connection.clone();
    let request_id = request_id.to_string();
    timed_call(CAPTURE_VERIFY_TIMEOUT, move || {
        let proxy = ZdrAuthenticatorProxyBlocking::new(&connection).map_err(|e| e.to_string())?;
        proxy.capture_verify(&request_id).map_err(|e| e.to_string())
    })
}

/// `CaptureVerifyAuthtok(request_id) -> (matched, reason, password)`.
/// One shot, root-only on the daemon side, only ever called after explicit
/// approval. `password` is the TPM-sealed login password and is non-empty
/// only when matched and a sealed password exists; it must never be logged.
fn call_capture_verify_authtok(
    connection: &Connection,
    request_id: &str,
) -> Result<(bool, String, Vec<u8>), String> {
    let connection = connection.clone();
    let request_id = request_id.to_string();
    timed_call(CAPTURE_VERIFY_TIMEOUT, move || {
        let proxy = ZdrAuthenticatorProxyBlocking::new(&connection).map_err(|e| e.to_string())?;
        proxy
            .capture_verify_authtok(&request_id)
            .map_err(|e| e.to_string())
    })
}

/// `Cancel(request_id) -> ()`, best-effort: the result is deliberately
/// ignored by callers on error paths.
fn cancel_best_effort(connection: &Connection, request_id: &str) {
    let connection = connection.clone();
    let request_id = request_id.to_string();
    let _ = timed_call(CANCEL_TIMEOUT, move || {
        let proxy = ZdrAuthenticatorProxyBlocking::new(&connection).map_err(|e| e.to_string())?;
        proxy.cancel(&request_id).map_err(|e| e.to_string())
    });
}

#[zbus::proxy(
    interface = "org.zdr.Authenticator",
    default_service = "org.zdr.Authenticator",
    default_path = "/org/zdr/Authenticator"
)]
trait ZdrAuthenticator {
    fn begin_auth(
        &self,
        user: &str,
        service: &str,
        tty: &str,
        label: &str,
    ) -> zbus::Result<(String, String)>;
    fn respond(&self, request_id: &str, approved: bool) -> zbus::Result<()>;
    fn await_consent(&self, request_id: &str) -> zbus::Result<String>;
    fn capture_verify(&self, request_id: &str) -> zbus::Result<(bool, String)>;
    fn capture_verify_authtok(&self, request_id: &str) -> zbus::Result<(bool, String, Vec<u8>)>;
    fn cancel(&self, request_id: &str) -> zbus::Result<()>;
}

/// Maximum number of characters kept in the display label sent to the daemon.
const LABEL_MAX_CHARS: usize = 120;

/// Consent state of a request, as reported by the daemon (`AwaitConsent`)
/// or derived locally from the terminal prompt (`Respond`).
pub(crate) enum Consent {
    Approved,
    Denied,
    Expired,
}

/// Module operating mode, selected by the `mode=` module argument.
///
/// `Decide` is the historical behaviour and the default: a face match alone
/// authenticates (`PAM_SUCCESS`). `Authtok` never authenticates by itself:
/// on a match it hands the TPM-released password to the rest of the stack
/// via `PAM_AUTHTOK` and returns `PAM_IGNORE`, leaving the decision to
/// `pam_unix`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Mode {
    Decide,
    Authtok,
}

/// Parse the `mode=` module argument. Pure.
///
/// No `mode=` argument means [`Mode::Decide`], so existing stack lines keep
/// their exact current behaviour. Unrelated arguments are ignored. If
/// `mode=` appears more than once the last occurrence wins. An unknown
/// value is an error: the caller logs it and fails closed with
/// `PAM_AUTH_ERR` rather than guessing a mode.
/// Parse the `quiet` module argument. Pure. Presence (exact token
/// `quiet`) suppresses the agent-channel PAM_TEXT_INFO hint; see the
/// agent branch for why modal polkit agents need that.
pub(crate) fn parse_quiet(args: &[&CStr]) -> bool {
    args.iter().any(|arg| arg.to_string_lossy() == "quiet")
}

pub(crate) fn parse_mode(args: &[&CStr]) -> Result<Mode, String> {
    let mut mode = Mode::Decide;
    for arg in args {
        let arg = arg.to_string_lossy();
        let Some(value) = arg.strip_prefix("mode=") else {
            continue;
        };
        mode = match value {
            "decide" => Mode::Decide,
            "authtok" => Mode::Authtok,
            _ => return Err(value.to_string()),
        };
    }
    Ok(mode)
}

/// Mode-aware mapping from (consent, capture result, token state) to a PAM
/// code.
///
/// `Decide` rows are exactly [`decide`]: approved + matched is
/// `PAM_SUCCESS`, everything else `PAM_AUTH_ERR`; the token flags are
/// ignored.
///
/// `Authtok` rows never return `PAM_SUCCESS` — a face match must not
/// authenticate by itself in this mode. Approved + matched returns
/// `PAM_IGNORE` (so `pam_unix` with `try_first_pass` validates the deposited
/// `PAM_AUTHTOK`, or prompts normally when none was deposited), except when
/// a token was present but storing it failed, which fails closed with
/// `PAM_AUTH_ERR` instead of silently degrading. Not matched, denied/
/// expired consent, and a capture that never ran all return `PAM_AUTH_ERR`.
pub(crate) fn decide_mode(
    mode: Mode,
    consent: &Consent,
    matched: Option<bool>,
    token_present: bool,
    token_set_ok: bool,
) -> PamResultCode {
    match mode {
        Mode::Decide => decide(consent, matched),
        Mode::Authtok => match (consent, matched) {
            (Consent::Approved, Some(true)) if token_present && !token_set_ok => {
                PamResultCode::PAM_AUTH_ERR
            }
            (Consent::Approved, Some(true)) => PamResultCode::PAM_IGNORE,
            _ => PamResultCode::PAM_AUTH_ERR,
        },
    }
}

/// Map a consent outcome plus the (optional) capture result to a PAM code.
///
/// Face authentication succeeds only when consent was explicitly approved
/// *and* the capture matched. `matched` is `None` when `CaptureVerify` was
/// never called (denied/expired) or itself failed; both fail closed. Every
/// non-success result lets the next module in the PAM stack (the password
/// prompt) run.
pub(crate) fn decide(consent: &Consent, matched: Option<bool>) -> PamResultCode {
    match (consent, matched) {
        (Consent::Approved, Some(true)) => PamResultCode::PAM_SUCCESS,
        _ => PamResultCode::PAM_AUTH_ERR,
    }
}

/// Parse the terminal consent answer. Only `y` or `yes` (any case, surrounding
/// whitespace ignored) mean yes; everything else — empty input, EOF (modelled
/// as empty/`None` by the caller), `n`, typos — means no.
pub(crate) fn parse_yes(answer: &str) -> bool {
    let answer = answer.trim().to_lowercase();
    answer == "y" || answer == "yes"
}

/// File-name component of a path-like token (`/usr/bin/sudo` -> `sudo`).
fn basename(token: &str) -> &str {
    let trimmed = token.trim_end_matches('/');
    match trimmed.rfind('/') {
        Some(index) => &trimmed[index + 1..],
        None => trimmed,
    }
}

/// Build the human-readable display label from a process argument vector.
///
/// Pure and defensive: the label is only ever *displayed* by the consent
/// agent, never acted on. `argv[0]` is reduced to its basename (a full path
/// is noise in a popup), a trivial duplication of that basename in `argv[1]`
/// is dropped, all control characters are stripped, whitespace runs are
/// collapsed to single spaces, and the result is capped at
/// [`LABEL_MAX_CHARS`] characters.
pub(crate) fn build_label(argv: &[String]) -> String {
    let mut tokens: Vec<String> = Vec::with_capacity(argv.len());
    if let Some((argv0, rest)) = argv.split_first() {
        let program = basename(argv0).to_string();
        if let Some((first, _)) = rest.split_first() {
            if basename(first) != program {
                tokens.push(program);
                tokens.extend(rest.iter().cloned());
            } else {
                // argv[1] merely repeats argv[0]'s basename: keep one copy.
                tokens.push(program);
                tokens.extend(rest.iter().skip(1).cloned());
            }
        } else {
            tokens.push(program);
        }
    }
    sanitize_label(&tokens.join(" "))
}

/// Strip control characters, collapse whitespace, cap the length.
fn sanitize_label(raw: &str) -> String {
    let without_controls: String = raw
        .chars()
        .filter(|c| !c.is_control() || c.is_whitespace())
        .collect();
    let collapsed = without_controls
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    collapsed
        .chars()
        .take(LABEL_MAX_CHARS)
        .collect::<String>()
        .trim_end()
        .to_string()
}

/// Read this process's command line for the display label. PAM cannot see
/// the command the user asked `sudo`/polkit to run; `/proc/self/cmdline`
/// (the authenticating process's own argv) is the closest display hint.
/// Non-UTF-8 bytes are lossy-converted and later sanitized anyway.
pub(crate) fn current_label() -> String {
    let Ok(bytes) = std::fs::read("/proc/self/cmdline") else {
        return String::new();
    };
    let argv: Vec<String> = bytes
        .split(|b| *b == 0)
        .filter(|part| !part.is_empty())
        .map(|part| String::from_utf8_lossy(part).into_owned())
        .collect();
    build_label(&argv)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn label_uses_basename_and_joins_args() {
        let argv = vec![
            "/usr/bin/sudo".into(),
            "-n".into(),
            "systemctl".into(),
            "restart".into(),
            "sshd".into(),
        ];
        assert_eq!(build_label(&argv), "sudo -n systemctl restart sshd");
    }

    #[test]
    fn label_drops_duplicated_basename() {
        let argv = vec!["/usr/bin/sudo".into(), "sudo".into(), "true".into()];
        assert_eq!(build_label(&argv), "sudo true");
        let argv = vec!["sudo".into(), "/usr/bin/sudo".into(), "true".into()];
        assert_eq!(build_label(&argv), "sudo true");
    }

    #[test]
    fn label_strips_controls_and_collapses_whitespace() {
        // ANSI escape, BEL, newline/tab and repeated spaces must not survive:
        // the label is rendered by another process's GUI/terminal.
        let argv = vec![
            "sudo\u{1b}[2J\u{7}".into(),
            "rm\n\t  -rf".into(),
            "/".into(),
        ];
        let label = build_label(&argv);
        assert_eq!(label, "sudo[2J rm -rf /");
        assert!(label.chars().all(|c| !c.is_control()));
    }

    #[test]
    fn label_caps_at_max_chars_on_char_boundary() {
        let hostile = "é".repeat(500);
        let argv = vec!["sudo".into(), hostile];
        let label = build_label(&argv);
        assert_eq!(label.chars().count(), LABEL_MAX_CHARS);
        assert!(label.starts_with("sudo "));
    }

    #[test]
    fn label_empty_argv_is_empty() {
        assert_eq!(build_label(&[]), "");
        assert_eq!(build_label(&[String::new()]), "");
    }

    #[test]
    fn yes_parser_accepts_only_y_or_yes() {
        for yes in ["y", "Y", "yes", "YES", "Yes", "  y  ", "\tyes\n"] {
            assert!(parse_yes(yes), "{yes:?} should mean yes");
        }
        for no in [
            "",
            "   ",
            "n",
            "N",
            "no",
            "yeah",
            "yep",
            "yess",
            "1",
            "yes please",
        ] {
            assert!(!parse_yes(no), "{no:?} should mean no");
        }
    }

    #[test]
    fn decide_only_approved_and_matched_succeeds() {
        assert_eq!(
            decide(&Consent::Approved, Some(true)),
            PamResultCode::PAM_SUCCESS
        );
        assert_eq!(
            decide(&Consent::Approved, Some(false)),
            PamResultCode::PAM_AUTH_ERR
        );
        assert_eq!(
            decide(&Consent::Approved, None),
            PamResultCode::PAM_AUTH_ERR
        );
        assert_eq!(
            decide(&Consent::Denied, Some(true)),
            PamResultCode::PAM_AUTH_ERR
        );
        assert_eq!(decide(&Consent::Denied, None), PamResultCode::PAM_AUTH_ERR);
        assert_eq!(
            decide(&Consent::Expired, Some(true)),
            PamResultCode::PAM_AUTH_ERR
        );
        assert_eq!(decide(&Consent::Expired, None), PamResultCode::PAM_AUTH_ERR);
    }

    fn quiet_of(args: &[&str]) -> bool {
        let owned: Vec<std::ffi::CString> = args
            .iter()
            .map(|a| std::ffi::CString::new(*a).unwrap_or_default())
            .collect();
        let refs: Vec<&CStr> = owned.iter().map(|a| a.as_c_str()).collect();
        parse_quiet(&refs)
    }

    #[test]
    fn quiet_requires_the_exact_token() {
        assert!(!quiet_of(&[]));
        assert!(quiet_of(&["quiet"]));
        assert!(quiet_of(&["mode=decide", "quiet"]));
        assert!(!quiet_of(&["quiet=1"]));
        assert!(!quiet_of(&["Quiet"]));
    }

    fn mode_of(args: &[&str]) -> Result<Mode, String> {
        let owned: Vec<std::ffi::CString> = args
            .iter()
            .map(|a| std::ffi::CString::new(*a).unwrap_or_default())
            .collect();
        let refs: Vec<&CStr> = owned.iter().map(|a| a.as_c_str()).collect();
        parse_mode(&refs)
    }

    #[test]
    fn mode_defaults_to_decide_without_mode_arg() {
        assert_eq!(mode_of(&[]), Ok(Mode::Decide));
        assert_eq!(mode_of(&["debug"]), Ok(Mode::Decide));
        // `mode` without `=`, and lookalike prefixes, are unrelated args.
        assert_eq!(mode_of(&["mode"]), Ok(Mode::Decide));
        assert_eq!(mode_of(&["xmode=authtok"]), Ok(Mode::Decide));
    }

    #[test]
    fn mode_parses_each_valid_value() {
        assert_eq!(mode_of(&["mode=decide"]), Ok(Mode::Decide));
        assert_eq!(mode_of(&["mode=authtok"]), Ok(Mode::Authtok));
    }

    #[test]
    fn mode_rejects_unknown_values() {
        assert_eq!(mode_of(&["mode=bogus"]), Err("bogus".to_string()));
        assert_eq!(mode_of(&["mode="]), Err(String::new()));
        assert_eq!(mode_of(&["mode=AUTHTOK"]), Err("AUTHTOK".to_string()));
        assert_eq!(
            mode_of(&["mode=authtok=extra"]),
            Err("authtok=extra".to_string())
        );
        // An unknown value fails even if a valid one follows it.
        assert_eq!(
            mode_of(&["mode=bogus", "mode=authtok"]),
            Err("bogus".to_string())
        );
    }

    #[test]
    fn mode_ignores_unrelated_args_and_last_duplicate_wins() {
        assert_eq!(
            mode_of(&["debug", "mode=authtok", "nullok"]),
            Ok(Mode::Authtok)
        );
        assert_eq!(mode_of(&["mode=authtok", "mode=decide"]), Ok(Mode::Decide));
        assert_eq!(
            mode_of(&["mode=decide", "debug", "mode=authtok"]),
            Ok(Mode::Authtok)
        );
    }

    fn consent(index: usize) -> Consent {
        match index {
            0 => Consent::Approved,
            1 => Consent::Denied,
            _ => Consent::Expired,
        }
    }

    #[test]
    fn decide_mode_decide_rows_are_unchanged() {
        // Decide mode must equal decide() for every input, token flags or not.
        for c in 0..3 {
            for matched in [None, Some(false), Some(true)] {
                for token_present in [false, true] {
                    for token_set_ok in [false, true] {
                        assert_eq!(
                            decide_mode(
                                Mode::Decide,
                                &consent(c),
                                matched,
                                token_present,
                                token_set_ok
                            ),
                            decide(&consent(c), matched),
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn decide_mode_authtok_rows() {
        let approved = Consent::Approved;
        // Matched with a sealed token, stored OK: hand off to pam_unix.
        assert_eq!(
            decide_mode(Mode::Authtok, &approved, Some(true), true, true),
            PamResultCode::PAM_IGNORE
        );
        // Matched but no blob enrolled: still PAM_IGNORE, no token set, so
        // the stack prompts normally; face alone never authenticates.
        assert_eq!(
            decide_mode(Mode::Authtok, &approved, Some(true), false, false),
            PamResultCode::PAM_IGNORE
        );
        // Token present but storing it failed: fail closed.
        assert_eq!(
            decide_mode(Mode::Authtok, &approved, Some(true), true, false),
            PamResultCode::PAM_AUTH_ERR
        );
        // Not matched, capture failed/never ran: fail closed.
        assert_eq!(
            decide_mode(Mode::Authtok, &approved, Some(false), false, false),
            PamResultCode::PAM_AUTH_ERR
        );
        assert_eq!(
            decide_mode(Mode::Authtok, &approved, None, false, false),
            PamResultCode::PAM_AUTH_ERR
        );
        // Denied/expired consent never reaches the token path.
        for c in [Consent::Denied, Consent::Expired] {
            assert_eq!(
                decide_mode(Mode::Authtok, &c, Some(true), true, true),
                PamResultCode::PAM_AUTH_ERR
            );
            assert_eq!(
                decide_mode(Mode::Authtok, &c, None, false, false),
                PamResultCode::PAM_AUTH_ERR
            );
        }
    }

    #[test]
    fn decide_mode_authtok_exhaustive() {
        for c in 0..3 {
            for matched in [None, Some(false), Some(true)] {
                for token_present in [false, true] {
                    for token_set_ok in [false, true] {
                        let expected =
                            if c == 0 && matched == Some(true) && !(token_present && !token_set_ok)
                            {
                                PamResultCode::PAM_IGNORE
                            } else {
                                PamResultCode::PAM_AUTH_ERR
                            };
                        assert_eq!(
                            decide_mode(
                                Mode::Authtok,
                                &consent(c),
                                matched,
                                token_present,
                                token_set_ok
                            ),
                            expected,
                            "consent={c} matched={matched:?} token_present={token_present} token_set_ok={token_set_ok}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn wipe_zeroes_buffer() {
        let mut buf = b"hunter2".to_vec();
        wipe(&mut buf);
        assert_eq!(buf, vec![0u8; 7]);
        let mut empty: Vec<u8> = Vec::new();
        wipe(&mut empty);
        assert!(empty.is_empty());
    }

    #[test]
    fn outcome_parser_rejects_unknown_outcomes() {
        assert!(matches!(parse_outcome("approved"), Some(Consent::Approved)));
        assert!(matches!(parse_outcome("denied"), Some(Consent::Denied)));
        assert!(matches!(parse_outcome("expired"), Some(Consent::Expired)));
        assert!(parse_outcome("Approved").is_none());
        assert!(parse_outcome("").is_none());
        assert!(parse_outcome("whatever").is_none());
    }
}
