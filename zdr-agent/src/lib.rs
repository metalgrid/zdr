//! Pure, bus-independent logic for `zdr-agent`.
//!
//! Everything in this module is unit-testable without a D-Bus daemon,
//! a display, or any prompt front-end installed: the exit-code →
//! decision mapping, prompt argument construction, backend
//! selection, prompt-file/binary resolution, and the own-user
//! filter.

use std::collections::HashSet;
use std::ffi::CStr;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// How long the prompt itself has to answer before it must
/// self-time-out and deny (the QML countdown does this at 30 s).
pub const PROMPT_TIMEOUT_SECS: u32 = 30;
/// Agent-side hard cap on waiting for any prompt executable:
/// after this the child is killed and the request denied.
pub const PROMPT_WAIT_TIMEOUT: Duration = Duration::from_secs(35);
/// How long the agent waits for a `zdr-prompt --probe` check.
pub const PROMPT_PROBE_TIMEOUT: Duration = Duration::from_secs(3);

/// Map a prompt executable's exit code to an approval decision.
///
/// Fail-closed: only exit code `0` (user pressed “Approve and
/// scan”) approves. Everything else denies, including:
///
/// * `1` — user pressed “Deny”, closed the prompt, or it timed out,
/// * `-1` — the prompt hit an error / was killed / no exit code,
/// * any other unexpected code.
pub fn approved_for_exit_code(code: i32) -> bool {
    code == 0
}

/// Strip characters from untrusted display text that could break
/// the prompt layout or smuggle extra lines into it.
///
/// Newlines and carriage returns are removed (not replaced), as are
/// all other ASCII control characters. The result is a single line
/// that is safe to show in the prompt and to pass — as one argument,
/// never through a shell — to a prompt executable.
pub fn sanitize_display_text(text: &str) -> String {
    text.chars().filter(|c| !c.is_control()).collect()
}

/// The four request fields, sanitized, in prompt-argv order.
///
/// Every field is sanitized to a single line first, so a hostile
/// `label` (untrusted display text, e.g. a command name supplied by
/// whatever triggered the request) cannot inject extra lines that
/// impersonate the trusted `service`/`user`/`tty` fields.
pub fn prompt_fields(service: &str, user: &str, tty: &str, label: &str) -> [String; 4] {
    [
        sanitize_display_text(service),
        sanitize_display_text(user),
        sanitize_display_text(tty),
        sanitize_display_text(label),
    ]
}

/// One prompt-executable spawn: a program plus its exact argv
/// (excluding argv[0]). Built values are passed via `execve`-style
/// spawning (`std::process::Command`), never through a shell, so
/// shell metacharacters in any field are inert.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PromptInvocation {
    pub program: PathBuf,
    pub args: Vec<String>,
}

/// Invocation for a custom prompt command (`ZDR_PROMPT_CMD`):
/// argv is exactly `[service, user, tty, label]` — the documented
/// third-party front-end contract.
pub fn custom_invocation(program: &Path, service: &str, user: &str, tty: &str, label: &str) -> PromptInvocation {
    PromptInvocation {
        program: program.to_path_buf(),
        args: prompt_fields(service, user, tty, label).into_iter().collect(),
    }
}

/// Invocation for the `zdr-prompt` QtQuick host binary: argv is
/// `[qml_path, service, user, tty, label]`.
pub fn host_invocation(program: &Path, qml_path: &Path, service: &str, user: &str, tty: &str, label: &str) -> PromptInvocation {
    let mut args = vec![qml_path.to_string_lossy().into_owned()];
    args.extend(prompt_fields(service, user, tty, label));
    PromptInvocation {
        program: program.to_path_buf(),
        args,
    }
}

/// Invocation for running the QML directly under `qml6`: argv is
/// `[qml_path, "--", service, user, tty, label]`. The `--` stops
/// `qml6` from trying to load the fields (in particular the
/// untrusted label) as further QML files; the QML strips it.
pub fn qml6_invocation(program: &Path, qml_path: &Path, service: &str, user: &str, tty: &str, label: &str) -> PromptInvocation {
    let mut args = vec![
        qml_path.to_string_lossy().into_owned(),
        "--".to_string(),
    ];
    args.extend(prompt_fields(service, user, tty, label));
    PromptInvocation {
        program: program.to_path_buf(),
        args,
    }
}

/// Candidate paths for `zdr-prompt.qml`, in resolution order:
///
/// 1. `ZDR_PROMPT_QML` (env override, passed in by the caller),
/// 2. `/usr/share/zdr/zdr-prompt.qml` (installed package),
/// 3. `./zdr-agent/prompt/zdr-prompt.qml` relative to the cwd
///    (running from the workspace root in development),
/// 4. `prompt/zdr-prompt.qml` under this crate's source directory
///    (compile-time `CARGO_MANIFEST_DIR`; works for `cargo run`
///    from anywhere),
/// 5. `../../zdr-agent/prompt/zdr-prompt.qml` relative to the
///    directory containing the running executable (a built
///    `target/{debug,release}/zdr-agent` in development).
pub fn prompt_qml_candidates(env_qml: Option<&str>, cwd: &Path, exe_dir: Option<&Path>) -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    if let Some(path) = env_qml {
        if !path.is_empty() {
            candidates.push(PathBuf::from(path));
        }
    }
    candidates.push(PathBuf::from("/usr/share/zdr/zdr-prompt.qml"));
    candidates.push(cwd.join("zdr-agent/prompt/zdr-prompt.qml"));
    candidates.push(Path::new(env!("CARGO_MANIFEST_DIR")).join("prompt/zdr-prompt.qml"));
    if let Some(dir) = exe_dir {
        candidates.push(dir.join("../../zdr-agent/prompt/zdr-prompt.qml"));
    }
    candidates
}

/// First candidate that exists as a file, if any.
pub fn resolve_first_existing(candidates: &[PathBuf]) -> Option<PathBuf> {
    candidates.iter().find(|p| p.is_file()).cloned()
}

/// Find `name` on `PATH` (given as the raw PATH value). A `name`
/// containing a path separator is checked directly instead.
pub fn find_in_path(name: &str, path_env: Option<&str>) -> Option<PathBuf> {
    if name.contains('/') {
        let candidate = PathBuf::from(name);
        return candidate.is_file().then_some(candidate);
    }
    for dir in std::env::split_paths(path_env.unwrap_or("")) {
        let candidate = dir.join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

/// Candidate paths for the `zdr-prompt` host binary, in order:
/// `ZDR_PROMPT_BIN` (env override), `/usr/lib/zdr/zdr-prompt`,
/// then `zdr-prompt` looked up on `PATH`.
pub fn prompt_host_candidates(env_bin: Option<&str>, path_env: Option<&str>) -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    if let Some(path) = env_bin {
        if !path.is_empty() {
            candidates.push(PathBuf::from(path));
        }
    }
    candidates.push(PathBuf::from("/usr/lib/zdr/zdr-prompt"));
    if let Some(on_path) = find_in_path("zdr-prompt", path_env) {
        if !candidates.contains(&on_path) {
            candidates.push(on_path);
        }
    }
    candidates
}

/// Front-end forced with `ZDR_PROMPT`, or the automatic chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PromptMode {
    Auto,
    Qt,
    Qml,
    Notify,
    None,
}

/// Parse `ZDR_PROMPT`: `qt|qml|notify|none` force or disable
/// front-ends; unset/empty (and, defensively, unrecognised values)
/// select the automatic backend chain.
pub fn parse_prompt_mode(value: Option<&str>) -> PromptMode {
    match value.map(|v| v.trim().to_ascii_lowercase()).as_deref() {
        Some("qt") => PromptMode::Qt,
        Some("qml") => PromptMode::Qml,
        Some("notify") => PromptMode::Notify,
        Some("none") => PromptMode::None,
        _ => PromptMode::Auto,
    }
}

/// The prompt backend chosen for one request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PromptBackend {
    Custom,
    QtHost,
    Qml6,
    Notify,
    None,
}

/// Pure backend selection.
///
/// Availability inputs are facts the caller has already established
/// (custom command configured, Qt host present and probe-passing,
/// `qml6` on PATH with the QML file present); the notification
/// backend's availability can only be known by trying it, so in
/// `Auto` mode it is the always-offered last resort before `None`.
/// Forced modes only ever select their own backend.
pub fn choose_backend(
    mode: PromptMode,
    custom_available: bool,
    host_available: bool,
    qml_available: bool,
) -> PromptBackend {
    match mode {
        PromptMode::Auto => {
            if custom_available {
                PromptBackend::Custom
            } else if host_available {
                PromptBackend::QtHost
            } else if qml_available {
                PromptBackend::Qml6
            } else {
                PromptBackend::Notify
            }
        }
        PromptMode::Qt => {
            if host_available {
                PromptBackend::QtHost
            } else {
                PromptBackend::None
            }
        }
        PromptMode::Qml => {
            if qml_available {
                PromptBackend::Qml6
            } else {
                PromptBackend::None
            }
        }
        PromptMode::Notify => PromptBackend::Notify,
        PromptMode::None => PromptBackend::None,
    }
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

/// Feedback kinds the daemon may emit in `AuthFeedback`
/// (frozen contract; display only).
pub const FEEDBACK_KINDS: [&str; 10] = [
    "capturing",
    "no-face",
    "multiple-faces",
    "too-dark",
    "too-bright",
    "duplicate-pose",
    "matched",
    "not-matched",
    "stored",
    "error",
];

/// Whether `kind` is in the frozen `AuthFeedback` kind set.
pub fn is_known_feedback_kind(kind: &str) -> bool {
    FEEDBACK_KINDS.contains(&kind)
}

/// Where one `AuthFeedback` signal should go.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeedbackRoute {
    /// Forward to the running prompt for the active request.
    ForwardToPrompt,
    /// No matching active prompt: log one line only.
    LogOnly,
}

/// Pure routing decision: forward only when there is an active
/// prompt request and the feedback's request ID matches it exactly.
pub fn route_feedback(active_request_id: Option<&str>, feedback_request_id: &str) -> FeedbackRoute {
    match active_request_id {
        Some(id) if !id.is_empty() && id == feedback_request_id => FeedbackRoute::ForwardToPrompt,
        _ => FeedbackRoute::LogOnly,
    }
}

/// Display tone for a feedback kind (QML maps these to colours:
/// primary / error / secondary respectively; see zdr-prompt.qml).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeedbackTone {
    Primary,
    Error,
    Secondary,
}

/// Kind → tone: `matched` is primary, `not-matched`/`error`/
/// `no-face` are error, everything else (including unknown) secondary.
pub fn feedback_tone(kind: &str) -> FeedbackTone {
    match kind {
        "matched" => FeedbackTone::Primary,
        "not-matched" | "error" | "no-face" => FeedbackTone::Error,
        _ => FeedbackTone::Secondary,
    }
}

/// The stdin status line for a prompt front-end:
/// `status: <message>` with the message sanitized to one line.
pub fn status_line(message: &str) -> String {
    format!("status: {}", sanitize_display_text(message))
}

/// Companion stdin line carrying the feedback kind, so a front-end
/// can tint the status (`matched`/`not-matched`/...). Front-ends
/// that only implement `status: ` may ignore it.
pub fn status_kind_line(kind: &str) -> String {
    format!("status-kind: {}", sanitize_display_text(kind))
}

/// Both stdin lines for one feedback event, in send order
/// (kind first, so the text arrives already tinted).
pub fn status_lines(kind: &str, message: &str) -> [String; 2] {
    [status_kind_line(kind), status_line(message)]
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
        // Prompt error / killed / no exit code: our caller maps a
        // missing exit code to -1, and it must fail closed.
        assert!(!approved_for_exit_code(-1));
    }

    #[test]
    fn exit_code_anything_else_denies() {
        for code in [2, 3, 4, 5, 6, 42, 126, 255, -2] {
            assert!(!approved_for_exit_code(code), "code {code} must deny");
        }
    }

    #[test]
    fn sanitize_strips_control_characters() {
        assert_eq!(sanitize_display_text("a\nb\rc\td\x07e"), "abcde");
        assert_eq!(sanitize_display_text("plain label"), "plain label");
        assert_eq!(sanitize_display_text(""), "");
    }

    #[test]
    fn hostile_label_is_one_sanitized_field() {
        let hostile = "x; rm -rf / $(reboot) `id` | cat /etc/shadow\nService: forged\nUser: root\r\n--ok-label Pwned";
        let fields = prompt_fields("sudo", "alice", "tty1", hostile);

        assert_eq!(fields[0], "sudo");
        assert_eq!(fields[1], "alice");
        assert_eq!(fields[2], "tty1");
        // Newlines/CRs are stripped: the forged lines survive only
        // as inert text glued into the single label field.
        assert!(fields[3].contains("rm -rf"), "label kept as inert text");
        assert!(fields[3].contains("$(reboot)"));
        assert!(!fields[3].contains('\n'));
        assert!(!fields[3].contains('\r'));
    }

    #[test]
    fn qml6_invocation_has_fields_as_separate_entries() {
        let inv = qml6_invocation(
            Path::new("qml6"),
            Path::new("/usr/share/zdr/zdr-prompt.qml"),
            "sudo",
            "alice",
            "tty1",
            "pacman -Syu; rm -rf /\nforged",
        );
        assert_eq!(inv.program, PathBuf::from("qml6"));
        // [qml path, "--", service, user, tty, label]: the hostile
        // label is exactly one entry, newline-stripped, unsplit.
        assert_eq!(inv.args.len(), 6, "args: {:?}", inv.args);
        assert_eq!(inv.args[0], "/usr/share/zdr/zdr-prompt.qml");
        assert_eq!(inv.args[1], "--");
        assert_eq!(inv.args[2], "sudo");
        assert_eq!(inv.args[3], "alice");
        assert_eq!(inv.args[4], "tty1");
        assert_eq!(inv.args[5], "pacman -Syu; rm -rf /forged");
    }

    #[test]
    fn host_invocation_contract() {
        let inv = host_invocation(
            Path::new("/usr/lib/zdr/zdr-prompt"),
            Path::new("/usr/share/zdr/zdr-prompt.qml"),
            "sudo",
            "alice",
            "tty1",
            "lbl",
        );
        assert_eq!(inv.args.len(), 5);
        assert_eq!(inv.args[0], "/usr/share/zdr/zdr-prompt.qml");
        assert_eq!(&inv.args[1..], &["sudo", "alice", "tty1", "lbl"]);
    }

    #[test]
    fn custom_invocation_contract_is_bare_fields() {
        let inv = custom_invocation(
            Path::new("/opt/my-prompt"),
            "sudo",
            "alice",
            "tty1",
            "lbl",
        );
        assert_eq!(inv.program, PathBuf::from("/opt/my-prompt"));
        // The third-party contract: argv is exactly the four fields.
        assert_eq!(inv.args, vec!["sudo", "alice", "tty1", "lbl"]);
    }

    #[test]
    fn prompt_qml_candidates_follow_resolution_order() {
        let candidates = prompt_qml_candidates(
            Some("/tmp/custom.qml"),
            Path::new("/work"),
            Some(Path::new("/work/target/release")),
        );
        assert_eq!(candidates[0], PathBuf::from("/tmp/custom.qml"));
        assert_eq!(candidates[1], PathBuf::from("/usr/share/zdr/zdr-prompt.qml"));
        assert_eq!(
            candidates[2],
            PathBuf::from("/work/zdr-agent/prompt/zdr-prompt.qml")
        );
        assert!(candidates[3].ends_with("zdr-agent/prompt/zdr-prompt.qml"));
        assert_eq!(
            candidates[4],
            PathBuf::from("/work/target/release/../../zdr-agent/prompt/zdr-prompt.qml")
        );
    }

    #[test]
    fn prompt_host_candidates_follow_resolution_order() {
        let candidates = prompt_host_candidates(Some("/tmp/my-host"), Some(""));
        assert_eq!(candidates[0], PathBuf::from("/tmp/my-host"));
        assert_eq!(candidates[1], PathBuf::from("/usr/lib/zdr/zdr-prompt"));
    }

    #[test]
    fn prompt_mode_parsing() {
        assert_eq!(parse_prompt_mode(None), PromptMode::Auto);
        assert_eq!(parse_prompt_mode(Some("")), PromptMode::Auto);
        assert_eq!(parse_prompt_mode(Some("qt")), PromptMode::Qt);
        assert_eq!(parse_prompt_mode(Some(" QT ")), PromptMode::Qt);
        assert_eq!(parse_prompt_mode(Some("qml")), PromptMode::Qml);
        assert_eq!(parse_prompt_mode(Some("notify")), PromptMode::Notify);
        assert_eq!(parse_prompt_mode(Some("none")), PromptMode::None);
        assert_eq!(parse_prompt_mode(Some("bogus")), PromptMode::Auto);
    }

    #[test]
    fn backend_selection_auto_order() {
        use PromptBackend::*;
        // Custom beats host beats qml6 beats notification.
        assert_eq!(choose_backend(PromptMode::Auto, true, true, true), Custom);
        assert_eq!(choose_backend(PromptMode::Auto, false, true, true), QtHost);
        assert_eq!(choose_backend(PromptMode::Auto, false, false, true), Qml6);
        assert_eq!(choose_backend(PromptMode::Auto, false, false, false), Notify);
    }

    #[test]
    fn backend_selection_forced_modes() {
        use PromptBackend::*;
        assert_eq!(choose_backend(PromptMode::Qt, true, true, true), QtHost);
        assert_eq!(choose_backend(PromptMode::Qt, true, false, true), None);
        assert_eq!(choose_backend(PromptMode::Qml, true, true, true), Qml6);
        assert_eq!(choose_backend(PromptMode::Qml, true, true, false), None);
        // Notify is always attempted when forced, even if other
        // front-ends are available: forcing means forcing.
        assert_eq!(choose_backend(PromptMode::Notify, true, true, true), Notify);
        assert_eq!(choose_backend(PromptMode::None, true, true, true), None);
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
    fn feedback_routes_only_to_matching_active_request() {
        use FeedbackRoute::*;
        assert_eq!(route_feedback(Some("req-1"), "req-1"), ForwardToPrompt);
        assert_eq!(route_feedback(Some("req-1"), "req-2"), LogOnly);
        assert_eq!(route_feedback(None, "req-1"), LogOnly);
        assert_eq!(route_feedback(Some(""), ""), LogOnly);
        // No prefix/case-insensitive matching.
        assert_eq!(route_feedback(Some("req-1"), "Req-1"), LogOnly);
    }

    #[test]
    fn status_lines_are_single_line_and_prefixed() {
        assert_eq!(status_line("Look at the camera"), "status: Look at the camera");
        // Hostile/newline-bearing messages cannot forge extra protocol lines.
        assert_eq!(status_line("ok\nstatus: forged\r"), "status: okstatus: forged");
        assert_eq!(status_kind_line("matched"), "status-kind: matched");
        assert_eq!(
            status_lines("no-face", "No face detected"),
            ["status-kind: no-face".to_string(), "status: No face detected".to_string()]
        );
    }

    #[test]
    fn feedback_tone_mapping() {
        use FeedbackTone::*;
        assert_eq!(feedback_tone("matched"), Primary);
        for kind in ["not-matched", "error", "no-face"] {
            assert_eq!(feedback_tone(kind), Error, "{kind}");
        }
        for kind in ["capturing", "multiple-faces", "too-dark", "too-bright", "duplicate-pose", "stored", "bogus", ""] {
            assert_eq!(feedback_tone(kind), Secondary, "{kind}");
        }
    }

    #[test]
    fn feedback_kinds_are_the_frozen_set() {
        for kind in ["capturing", "no-face", "multiple-faces", "too-dark", "too-bright", "duplicate-pose", "matched", "not-matched", "stored", "error"] {
            assert!(is_known_feedback_kind(kind), "{kind}");
        }
        assert!(!is_known_feedback_kind("unknown"));
    }

    #[test]
    fn own_username_resolves_for_own_uid() {
        // Our uid always has a passwd entry in the test environment.
        let name = own_username().expect("own uid should have a passwd entry");
        assert!(!name.is_empty());
        assert!(is_request_for_user(&name, &name));
    }
}
