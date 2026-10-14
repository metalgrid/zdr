extern crate pam;

use zbus::blocking::Connection;

use pam::constants::{PamFlag, PamResultCode};
use pam::module::{PamHandle, PamHooks};
use pam::pam_try;
use std::ffi::CStr;

struct PamZdr;
pam::pam_hooks!(PamZdr);

impl PamHooks for PamZdr {
    // This function performs the task of authenticating the user.
    fn sm_authenticate(pamh: &mut PamHandle, _args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        match Connection::system() {
            Err(e) => {
                println!("Zdr error: {}", e);
                PamResultCode::PAM_AUTH_ERR
            }
            Ok(connection) => match ZdrAuthenticatorProxyBlocking::new(&connection) {
                Err(e) => {
                    println!("Zdr error: {}", e);
                    PamResultCode::PAM_AUTH_ERR
                }
                Ok(auth) => {
                    let user = pam_try!(pamh.get_user(None));
                    match auth.verify(&user) {
                        Ok(success) => {
                            if success {
                                PamResultCode::PAM_SUCCESS
                            } else {
                                PamResultCode::PAM_AUTH_ERR
                            }
                        }
                        Err(e) => {
                            println!("Zdr error: {}", e);
                            PamResultCode::PAM_AUTH_ERR
                        }
                    }
                }
            },
        }
    }

    fn sm_setcred(_pamh: &mut PamHandle, _args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        PamResultCode::PAM_SUCCESS
    }

    fn acct_mgmt(_pamh: &mut PamHandle, _args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        PamResultCode::PAM_SUCCESS
    }
}

#[zbus::proxy(
    interface = "org.zdr.Authenticator",
    default_service = "org.zdr.Authenticator",
    default_path = "/org/zdr/Authenticator"
)]
trait ZdrAuthenticator {
    fn verify(&self, user: &str) -> Result<bool, zbus::fdo::Error>;
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
    let collapsed = without_controls.split_whitespace().collect::<Vec<_>>().join(" ");
    collapsed.chars().take(LABEL_MAX_CHARS).collect::<String>().trim_end().to_string()
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
        let argv = vec!["/usr/bin/sudo".into(), "-n".into(), "systemctl".into(), "restart".into(), "sshd".into()];
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
        let argv = vec!["sudo\u{1b}[2J\u{7}".into(), "rm\n\t  -rf".into(), "/".into()];
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
        for no in ["", "   ", "n", "N", "no", "yeah", "yep", "yess", "1", "yes please"] {
            assert!(!parse_yes(no), "{no:?} should mean no");
        }
    }

    #[test]
    fn decide_only_approved_and_matched_succeeds() {
        assert_eq!(decide(&Consent::Approved, Some(true)), PamResultCode::PAM_SUCCESS);
        assert_eq!(decide(&Consent::Approved, Some(false)), PamResultCode::PAM_AUTH_ERR);
        assert_eq!(decide(&Consent::Approved, None), PamResultCode::PAM_AUTH_ERR);
        assert_eq!(decide(&Consent::Denied, Some(true)), PamResultCode::PAM_AUTH_ERR);
        assert_eq!(decide(&Consent::Denied, None), PamResultCode::PAM_AUTH_ERR);
        assert_eq!(decide(&Consent::Expired, Some(true)), PamResultCode::PAM_AUTH_ERR);
        assert_eq!(decide(&Consent::Expired, None), PamResultCode::PAM_AUTH_ERR);
    }
}
