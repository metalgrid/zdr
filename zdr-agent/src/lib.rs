//! Pure, bus-independent logic for `zdr-agent`.
//!
//! Everything in this module is unit-testable without a D-Bus daemon,
//! a display, or `zenity` installed: the exit-code → decision mapping,
//! popup text/argument construction, and the own-user filter.

use std::collections::HashSet;
use std::ffi::CStr;

/// Title shown on every authentication popup.
pub const POPUP_TITLE: &str = "Face authentication requested";
/// Label of the affirmative (approve) button.
pub const APPROVE_LABEL: &str = "Approve and scan";
/// Label of the negative (deny) button.
pub const DENY_LABEL: &str = "Deny";
/// Popup auto-dismiss timeout, in seconds (zenity `--timeout`).
pub const POPUP_TIMEOUT_SECS: u32 = 30;

/// Map a `zenity --question` exit code to an approval decision.
///
/// Fail-closed: only exit code `0` (user pressed “Approve and scan”)
/// approves. Everything else denies, including:
///
/// * `1` — user pressed “Deny” (or closed the dialog),
/// * `-1` — zenity hit an error / was killed / no exit code available,
/// * `5` — the `--timeout` elapsed with no answer,
/// * any other unexpected code.
pub fn approved_for_exit_code(code: i32) -> bool {
    code == 0
}

/// Strip characters from untrusted display text that could break the
/// popup layout or smuggle extra lines into it.
///
/// Newlines and carriage returns are removed (not replaced), as are
/// all other ASCII control characters. The result is a single line
/// that is safe to embed in the popup text and to pass — as one
/// argument, never through a shell — to `zenity`.
pub fn sanitize_display_text(text: &str) -> String {
    text.chars().filter(|c| !c.is_control()).collect()
}

/// Build the multi-line popup body for one authentication request.
///
/// Every field is sanitized to a single line first, so a hostile
/// `label` (untrusted display text, e.g. a command name supplied by
/// whatever triggered the request) cannot inject extra lines that
/// impersonate the trusted `service`/`user`/`tty` fields.
pub fn build_popup_text(service: &str, user: &str, tty: &str, label: &str) -> String {
    format!(
        "Service: {}\nUser: {}\nTTY: {}\nCommand: {}",
        sanitize_display_text(service),
        sanitize_display_text(user),
        sanitize_display_text(tty),
        sanitize_display_text(label),
    )
}

/// Build the exact argument vector used to spawn `zenity`.
///
/// The popup text (including the untrusted label) is a single
/// element of this vector and is passed via `execve`-style spawning
/// (`std::process::Command`), never through a shell, so shell
/// metacharacters in the label are inert.
pub fn zenity_args(popup_text: &str) -> Vec<String> {
    vec![
        "--question".to_string(),
        "--title".to_string(),
        POPUP_TITLE.to_string(),
        "--text".to_string(),
        popup_text.to_string(),
        "--ok-label".to_string(),
        APPROVE_LABEL.to_string(),
        "--cancel-label".to_string(),
        DENY_LABEL.to_string(),
        "--timeout".to_string(),
        POPUP_TIMEOUT_SECS.to_string(),
    ]
}

/// Decide whether a request addressed to `request_user` is ours.
///
/// The comparison is exact string equality against our own username
/// as resolved from our uid via `getpwuid` (see [`own_username`]) —
/// never against `$USER`, which any process can set arbitrarily.
pub fn is_request_for_user(request_user: &str, own_username: &str) -> bool {
    !own_username.is_empty() && request_user == own_username
}

/// Tracks request IDs already handled on this connection, so a
/// duplicate `AuthRequested` for the same request is dropped instead
/// of showing a second popup (or sending a second response).
#[derive(Debug, Default)]
pub struct SeenRequests {
    ids: HashSet<String>,
}

impl SeenRequests {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record `request_id`; returns `true` if it is new and should
    /// be handled, `false` if it is a duplicate to drop.
    pub fn mark_seen(&mut self, request_id: &str) -> bool {
        self.ids.insert(request_id.to_string())
    }
}

/// Our own uid, from `getuid(2)` — not from the environment.
pub fn own_uid() -> u32 {
    // SAFETY: getuid always succeeds and has no preconditions.
    unsafe { libc::getuid() }
}

/// Resolve a uid to its login name via `getpwuid(3)`.
///
/// Returns `None` if the uid has no passwd entry. The returned
/// string is copied out of `getpwuid`'s static storage before any
/// other libc call can overwrite it.
pub fn username_for_uid(uid: u32) -> Option<String> {
    // SAFETY: getpwuid accepts any uid; a null return means "no
    // entry" and is checked before dereferencing. pw_name is a
    // NUL-terminated string owned by the passwd database.
    unsafe {
        let pw = libc::getpwuid(uid);
        if pw.is_null() || (*pw).pw_name.is_null() {
            return None;
        }
        Some(CStr::from_ptr((*pw).pw_name).to_string_lossy().into_owned())
    }
}

/// Our own login name, resolved from our own uid via `getpwuid`.
pub fn own_username() -> Option<String> {
    username_for_uid(own_uid())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_code_zero_approves() {
        assert!(approved_for_exit_code(0));
    }

    #[test]
    fn exit_code_deny_denies() {
        assert!(!approved_for_exit_code(1));
    }

    #[test]
    fn exit_code_error_denies() {
        // zenity error / killed / no exit code: our caller maps a
        // missing exit code to -1, and it must fail closed.
        assert!(!approved_for_exit_code(-1));
    }

    #[test]
    fn exit_code_timeout_denies() {
        assert!(!approved_for_exit_code(5));
    }

    #[test]
    fn exit_code_anything_else_denies() {
        for code in [2, 3, 4, 6, 42, 126, 255, -2] {
            assert!(!approved_for_exit_code(code), "code {code} must deny");
        }
    }

    #[test]
    fn popup_text_lists_all_fields() {
        let text = build_popup_text("sudo", "alice", "tty1", "pacman -Syu");
        assert_eq!(
            text,
            "Service: sudo\nUser: alice\nTTY: tty1\nCommand: pacman -Syu"
        );
    }

    #[test]
    fn hostile_label_stays_one_argument_and_loses_newlines() {
        let hostile = "x; rm -rf / $(reboot) `id` | cat /etc/shadow\nService: forged\nUser: root\r\n--ok-label Pwned";
        let text = build_popup_text("sudo", "alice", "tty1", hostile);

        // Newlines/CRs from the label are stripped: the text still
        // has exactly the four lines we built, nothing forged.
        assert_eq!(text.lines().count(), 4, "popup text: {text:?}");
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines[0], "Service: sudo");
        assert_eq!(lines[1], "User: alice");
        assert_eq!(lines[2], "TTY: tty1");
        // The forged lines survive only as inert text glued onto
        // the end of the Command line, never as fields of their own.
        assert!(lines[3].starts_with("Command: "));
        assert!(!text.contains('\r'));

        let args = zenity_args(&text);

        // Fixed argument count: the hostile label did not split
        // into extra arguments, and no shell ever sees it.
        assert_eq!(args.len(), 11, "args: {args:?}");
        let text_arg = &args[4];
        assert!(text_arg.contains("rm -rf"), "label kept as inert text");
        assert!(text_arg.contains("$(reboot)"));
        assert!(!text_arg.contains('\n') || text_arg.matches('\n').count() == 3);
        // The only newlines in the text argument are our three
        // field separators.
        assert_eq!(text_arg.matches('\n').count(), 3);
        // Our button labels, not the label's forged ones, win.
        assert_eq!(args[6], APPROVE_LABEL);
        assert_eq!(args[8], DENY_LABEL);
    }

    #[test]
    fn zenity_args_match_contract() {
        let args = zenity_args("body");
        assert_eq!(args[0], "--question");
        assert_eq!(args[1], "--title");
        assert_eq!(args[2], "Face authentication requested");
        assert_eq!(args[3], "--text");
        assert_eq!(args[4], "body");
        assert_eq!(args[5], "--ok-label");
        assert_eq!(args[6], "Approve and scan");
        assert_eq!(args[7], "--cancel-label");
        assert_eq!(args[8], "Deny");
        assert_eq!(args[9], "--timeout");
        assert_eq!(args[10], "30");
    }

    #[test]
    fn sanitize_strips_control_characters() {
        assert_eq!(sanitize_display_text("a\nb\rc\td\x07e"), "abcde");
        assert_eq!(sanitize_display_text("plain label"), "plain label");
        assert_eq!(sanitize_display_text(""), "");
    }

    #[test]
    fn other_user_requests_are_filtered_out() {
        assert!(is_request_for_user("alice", "alice"));
        assert!(!is_request_for_user("bob", "alice"));
        assert!(!is_request_for_user("root", "alice"));
        assert!(!is_request_for_user("", "alice"));
        assert!(!is_request_for_user("alice", ""));
        // No prefix/substring or case-insensitive matches.
        assert!(!is_request_for_user("alice2", "alice"));
        assert!(!is_request_for_user("Alice", "alice"));
    }

    #[test]
    fn duplicate_request_ids_are_dropped() {
        let mut seen = SeenRequests::new();
        assert!(seen.mark_seen("req-1"));
        assert!(!seen.mark_seen("req-1"));
        assert!(seen.mark_seen("req-2"));
        assert!(!seen.mark_seen("req-1"));
    }

    #[test]
    fn own_username_resolves_for_own_uid() {
        // Our uid always has a passwd entry in the test environment.
        let name = own_username().expect("own uid should have a passwd entry");
        assert!(!name.is_empty());
        assert!(is_request_for_user(&name, &name));
    }
}
