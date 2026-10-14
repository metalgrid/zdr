//! TPM-sealed password storage (Step 15): a thin wrapper around
//! `systemd-creds` run as a subprocess. `systemd-creds` is the TPM
//! boundary on purpose — this daemon does not link any TSS library.
//!
//! Seal: `systemd-creds encrypt --name=zdr-password --with-key=tpm2
//! [--tpm2-pcrs=<pcrs>] - <tmpfile>`, with the password fed on stdin
//! and the sealed blob then renamed to
//! `<auth-dir>/<user>/password.cred` (mode 0600).
//! Unseal: `systemd-creds decrypt --name=zdr-password --newline=no
//! <path> -`, capturing stdout. `--name` is required on decrypt too:
//! the credential name is bound into the blob, and `password.cred`
//! alone would derive a different expected name. `--newline=no`
//! keeps the released bytes exactly the enrolled bytes.
//!
//! Empty PCR config: `systemd-creds` 262 *accepts* `--tpm2-pcrs=`
//! (empty) on encrypt, but the credential it then produced could not
//! be decrypted again (the credentials service answered
//! PermissionDenied in local checks), so an empty `tpm_pcrs` here
//! means "omit the `--tpm2-pcrs` flag entirely", i.e. seal to the
//! TPM with no PCR policy. Non-empty values are validated as
//! `+`-separated PCR numbers (0..=23) before they ever reach argv.
//!
//! The password never appears in argv, the environment, or logs.
//! Child stderr is captured only to note that a failure happened; it
//! is never included in errors (it must never become a channel that
//! could echo anything sensitive back into a journal).
//!
//! Zeroization honesty: [`SecretBytes`] zeroes the buffers *this
//! crate owns* on drop (enrollment input copy, unseal output, the
//! worker copy handed to the D-Bus layer). It cannot erase copies
//! made by the allocator before a buffer grew, by zbus while it
//! materialized the `EnrollPassword` argument `String`, or the final
//! `password` byte vector owned by the D-Bus return value — that one
//! is the caller's (root PAM) property by design. The D-Bus layer
//! converts its `String` immediately and drops the daemon-owned
//! `SecretBytes` before the return path completes.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Credential name bound into every sealed blob (`--name`).
pub const CRED_NAME: &str = "zdr-password";
/// Sealed-blob file name inside `<auth-dir>/<user>/`.
pub const PASSWORD_CRED_FILE: &str = "password.cred";
/// Name of the binary that is our TPM boundary.
pub const SYSTEMD_CREDS: &str = "systemd-creds";
/// Hard cap for one `systemd-creds` invocation.
pub const SEAL_TIMEOUT: Duration = Duration::from_secs(10);

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Overwrite `buf` in place so the compiler cannot elide the writes.
pub fn zeroize_slice(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        // SAFETY: `b` is a live, writable byte of `buf`.
        unsafe { std::ptr::write_volatile(b, 0) };
    }
    std::sync::atomic::compiler_fence(Ordering::SeqCst);
}

/// Password bytes owned by zdrd. Zeroed on drop; `Debug` is redacted
/// so an accidental `{:?}` in a log line cannot leak contents.
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    pub fn new(bytes: Vec<u8>) -> Self {
        SecretBytes(bytes)
    }

    pub fn from_slice(bytes: &[u8]) -> Self {
        SecretBytes(bytes.to_vec())
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Zero the contents now (drop would do it anyway).
    pub fn zeroize(&mut self) {
        zeroize_slice(&mut self.0);
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl std::fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecretBytes(<redacted>, {} bytes)", self.0.len())
    }
}

/// Short, secret-free failure for a `systemd-creds` invocation.
/// Never carries child stderr or any stdin material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SealError {
    /// The child could not be spawned at all.
    Spawn(String),
    /// The child exceeded its timeout and was killed.
    Timeout,
    /// The child exited unsuccessfully (status kept, stderr dropped).
    Failed(Option<i32>),
    /// Local filesystem work around the child failed.
    Io(String),
    /// Bad local input (empty password, invalid PCR spec, bad user).
    Invalid(String),
}

impl std::fmt::Display for SealError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SealError::Spawn(e) => write!(f, "spawning {SYSTEMD_CREDS} failed: {e}"),
            SealError::Timeout => {
                write!(
                    f,
                    "{SYSTEMD_CREDS} timed out after {}s",
                    SEAL_TIMEOUT.as_secs()
                )
            }
            SealError::Failed(Some(code)) => {
                write!(f, "{SYSTEMD_CREDS} failed with exit status {code}")
            }
            SealError::Failed(None) => write!(f, "{SYSTEMD_CREDS} failed (killed by signal)"),
            SealError::Io(e) => write!(f, "sealed-password storage I/O failed: {e}"),
            SealError::Invalid(e) => write!(f, "invalid sealed-password request: {e}"),
        }
    }
}

impl std::error::Error for SealError {}

/// Raw child result handed back by a [`CommandRunner`]. For decrypt,
/// `stdout` is the plaintext password: the sealer moves it straight
/// into a [`SecretBytes`] without copying.
#[derive(Debug)]
pub struct CommandOutput {
    pub success: bool,
    pub status: Option<i32>,
    pub stdout: Vec<u8>,
    /// Captured so the child cannot block on a full pipe; its
    /// contents are deliberately never read into errors or logs.
    #[allow(dead_code)]
    pub stderr: Vec<u8>,
}

/// Runs one external command with stdin bytes and a timeout. This is
/// the injection seam for tests: a fake runner records argv and
/// *whether stdin was present* — not its contents — so tests never
/// need a TPM or `systemd-creds`, and never record a password.
pub trait CommandRunner: Send + Sync {
    fn run(
        &self,
        argv: &[String],
        stdin: &[u8],
        timeout: Duration,
    ) -> Result<CommandOutput, SealError>;
}

/// The production runner: a real `systemd-creds` subprocess. It is
/// only constructed by the daemon; unit tests use a fake instead.
pub struct SystemCommandRunner;

impl CommandRunner for SystemCommandRunner {
    fn run(
        &self,
        argv: &[String],
        stdin: &[u8],
        timeout: Duration,
    ) -> Result<CommandOutput, SealError> {
        let (program, args) = argv
            .split_first()
            .ok_or_else(|| SealError::Invalid("empty argv".to_string()))?;
        let mut child = Command::new(program)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| SealError::Spawn(e.to_string()))?;

        // Drain stdout/stderr on side threads so a chatty child cannot
        // deadlock against a full pipe while we feed it stdin.
        let stdout_thread = child.stdout.take().map(|mut pipe| {
            std::thread::spawn(move || {
                let mut buf = Vec::new();
                let _ = pipe.read_to_end(&mut buf);
                buf
            })
        });
        let stderr_thread = child.stderr.take().map(|mut pipe| {
            std::thread::spawn(move || {
                let mut buf = Vec::new();
                let _ = pipe.read_to_end(&mut buf);
                buf
            })
        });

        if let Some(mut pipe) = child.stdin.take() {
            // A child that exits early makes this a broken pipe: that
            // is the child's failure to report, not a write panic.
            let _ = pipe.write_all(stdin);
            let _ = pipe.flush();
        }

        let deadline = Instant::now() + timeout;
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) => {
                    if Instant::now() >= deadline {
                        let _ = child.kill();
                        let _ = child.wait();
                        // Reap the drain threads; contents discarded.
                        if let Some(t) = stdout_thread {
                            let _ = t.join();
                        }
                        if let Some(t) = stderr_thread {
                            let _ = t.join();
                        }
                        return Err(SealError::Timeout);
                    }
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(e) => return Err(SealError::Spawn(e.to_string())),
            }
        };
        let stdout = match stdout_thread {
            Some(t) => t.join().unwrap_or_default(),
            None => Vec::new(),
        };
        let stderr = match stderr_thread {
            Some(t) => t.join().unwrap_or_default(),
            None => Vec::new(),
        };
        Ok(CommandOutput {
            success: status.success(),
            status: status.code(),
            stdout,
            stderr,
        })
    }
}

/// Validate a PCR spec: empty (no binding) or `+`-separated numbers
/// in 0..=23, as `systemd-creds --tpm2-pcrs` expects (`7`, `7+11`).
pub fn valid_pcrs(pcrs: &str) -> bool {
    if pcrs.is_empty() {
        return true;
    }
    pcrs.split('+').all(|part| {
        !part.is_empty()
            && part.bytes().all(|b| b.is_ascii_digit())
            && part.parse::<u32>().map(|n| n <= 23).unwrap_or(false)
    })
}

/// argv for sealing. The output path is the *temporary* file the
/// caller renames into place; stdin carries the password, so the
/// password is deliberately not an argument. No `--tpm2-pcrs` flag
/// at all when `pcrs` is empty (see module docs).
pub fn encrypt_argv(pcrs: &str, out: &Path) -> Result<Vec<String>, SealError> {
    if !valid_pcrs(pcrs) {
        return Err(SealError::Invalid(format!(
            "invalid TPM PCR spec {pcrs:?} (want e.g. \"7\" or \"7+11\")"
        )));
    }
    let mut argv = vec![
        SYSTEMD_CREDS.to_string(),
        "encrypt".to_string(),
        format!("--name={CRED_NAME}"),
        "--with-key=tpm2".to_string(),
    ];
    if !pcrs.is_empty() {
        argv.push(format!("--tpm2-pcrs={pcrs}"));
    }
    argv.push("-".to_string());
    argv.push(out.display().to_string());
    Ok(argv)
}

/// argv for unsealing `<path>` to stdout.
pub fn decrypt_argv(path: &Path) -> Vec<String> {
    vec![
        SYSTEMD_CREDS.to_string(),
        "decrypt".to_string(),
        format!("--name={CRED_NAME}"),
        "--newline=no".to_string(),
        path.display().to_string(),
        "-".to_string(),
    ]
}

fn short_io(context: &Path, e: std::io::Error) -> SealError {
    SealError::Io(format!("{}: {e}", context.display()))
}

/// Seals and unseals per-user passwords through a [`CommandRunner`].
pub struct PasswordSealer {
    pcrs: String,
    runner: Arc<dyn CommandRunner>,
}

impl PasswordSealer {
    /// Production sealer backed by the real `systemd-creds`.
    pub fn new(pcrs: String) -> Self {
        PasswordSealer {
            pcrs,
            runner: Arc::new(SystemCommandRunner),
        }
    }

    /// Sealer over an injected runner (unit tests, fakes).
    pub fn with_runner(pcrs: String, runner: Arc<dyn CommandRunner>) -> Self {
        PasswordSealer { pcrs, runner }
    }

    /// Seal `password` to `out_path`. Writes to a unique temporary
    /// file in the same directory first (`systemd-creds` refuses to
    /// overwrite an existing output), then renames over `out_path`
    /// so re-enrollment atomically replaces a stale blob. The final
    /// file is mode 0600 and its directory 0700 (unix).
    pub fn seal(&self, password: &SecretBytes, out_path: &Path) -> Result<(), SealError> {
        if password.is_empty() {
            return Err(SealError::Invalid("empty password".to_string()));
        }
        let dir = out_path.parent().ok_or_else(|| {
            SealError::Invalid(format!("no parent directory for {}", out_path.display()))
        })?;
        std::fs::create_dir_all(dir).map_err(|e| short_io(dir, e))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
        }
        let n = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let tmp_path = dir.join(format!(".password.cred.tmp-{}-{n}", std::process::id()));
        let result = (|| -> Result<(), SealError> {
            let argv = encrypt_argv(&self.pcrs, &tmp_path)?;
            let output = self.runner.run(&argv, password.as_slice(), SEAL_TIMEOUT)?;
            if !output.success {
                // Stderr is dropped on purpose (module docs).
                return Err(SealError::Failed(output.status));
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o600))
                    .map_err(|e| short_io(&tmp_path, e))?;
            }
            std::fs::rename(&tmp_path, out_path).map_err(|e| short_io(out_path, e))?;
            Ok(())
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&tmp_path);
        }
        result
    }

    /// Unseal the blob at `path`. No filesystem writes; the plaintext
    /// moves from the runner output straight into a [`SecretBytes`].
    pub fn unseal(&self, path: &Path) -> Result<SecretBytes, SealError> {
        let argv = decrypt_argv(path);
        let output = self.runner.run(&argv, &[], SEAL_TIMEOUT)?;
        if !output.success {
            return Err(SealError::Failed(output.status));
        }
        Ok(SecretBytes::new(output.stdout))
    }
}

/// `<auth-dir>/<user>/password.cred`, or `None` for an invalid user.
pub fn password_cred_path(auth_dir: &Path, user: &str) -> Option<PathBuf> {
    if !crate::templates::valid_user(user) {
        return None;
    }
    Some(auth_dir.join(user).join(PASSWORD_CRED_FILE))
}

/// Existence only — never reads the blob. Any uid may learn this.
pub fn has_sealed_password(auth_dir: &Path, user: &str) -> bool {
    match password_cred_path(auth_dir, user) {
        Some(path) => path.is_file(),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    const SECRET: &[u8] = b"correct horse battery staple";

    #[derive(Default)]
    struct FakeCall {
        argv: Vec<String>,
        stdin_present: bool,
        stdin_len: usize,
    }

    /// Records argv and stdin *presence/length only* — never stdin
    /// contents — and replays a canned result. On a fake encrypt it
    /// creates the output file the real tool would have written, so
    /// the sealer's rename path is exercised.
    struct FakeRunner {
        calls: Mutex<Vec<FakeCall>>,
        stdout: Vec<u8>,
        stderr: Vec<u8>,
        success: bool,
        error: Option<SealError>,
    }

    impl FakeRunner {
        fn new(stdout: Vec<u8>, success: bool) -> Self {
            FakeRunner {
                calls: Mutex::new(Vec::new()),
                stdout,
                stderr: Vec::new(),
                success,
                error: None,
            }
        }
    }

    impl CommandRunner for FakeRunner {
        fn run(
            &self,
            argv: &[String],
            stdin: &[u8],
            _timeout: Duration,
        ) -> Result<CommandOutput, SealError> {
            match self.calls.lock() {
                Ok(mut calls) => calls.push(FakeCall {
                    argv: argv.to_vec(),
                    stdin_present: !stdin.is_empty(),
                    stdin_len: stdin.len(),
                }),
                Err(_) => return Err(SealError::Invalid("fake lock poisoned".into())),
            }
            if let Some(e) = &self.error {
                return Err(e.clone());
            }
            if argv.iter().any(|a| a == "encrypt") {
                if let Some(out) = argv.last() {
                    std::fs::write(out, b"fake sealed blob")
                        .map_err(|e| SealError::Io(e.to_string()))?;
                }
            }
            Ok(CommandOutput {
                success: self.success,
                status: if self.success { Some(0) } else { Some(1) },
                stdout: self.stdout.clone(),
                stderr: self.stderr.clone(),
            })
        }
    }

    fn temp_dir(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("zdrd-seal-test-{}-{}", std::process::id(), tag));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        dir
    }

    #[test]
    fn secret_bytes_zeroize_and_redacted_debug() {
        let mut secret = SecretBytes::from_slice(SECRET);
        assert_eq!(secret.len(), SECRET.len());
        assert!(!format!("{secret:?}").contains("correct"));
        secret.zeroize();
        assert!(secret.as_slice().iter().all(|b| *b == 0));
        let mut raw = vec![1u8, 2, 3];
        zeroize_slice(&mut raw);
        assert_eq!(raw, vec![0, 0, 0]);
    }

    #[test]
    fn encrypt_argv_binds_tpm_and_pcrs_without_password() {
        let argv = encrypt_argv("7", Path::new("/tmp/x/password.cred")).expect("argv");
        assert_eq!(argv[0], "systemd-creds");
        assert_eq!(argv[1], "encrypt");
        assert!(argv.contains(&"--name=zdr-password".to_string()));
        assert!(argv.contains(&"--with-key=tpm2".to_string()));
        assert!(argv.contains(&"--tpm2-pcrs=7".to_string()));
        assert_eq!(argv[argv.len() - 2], "-");
        assert_eq!(argv[argv.len() - 1], "/tmp/x/password.cred");
        let secret_text = String::from_utf8_lossy(SECRET).into_owned();
        assert!(argv.iter().all(|a| !a.contains(&secret_text)));
    }

    #[test]
    fn encrypt_argv_empty_pcrs_omits_flag_and_invalid_pcrs_rejected() {
        let argv = encrypt_argv("", Path::new("/tmp/x/password.cred")).expect("argv");
        assert!(argv.iter().all(|a| !a.starts_with("--tpm2-pcrs")));
        for bad in ["abc", "7;rm", "7++11", "24", "-1", "7 "] {
            assert!(
                encrypt_argv(bad, Path::new("/tmp/x")).is_err(),
                "pcrs {bad:?}"
            );
            assert!(!valid_pcrs(bad), "valid_pcrs {bad:?}");
        }
        assert!(valid_pcrs(""));
        assert!(valid_pcrs("7"));
        assert!(valid_pcrs("7+11+23"));
    }

    #[test]
    fn decrypt_argv_names_credential_and_keeps_bytes_exact() {
        let argv = decrypt_argv(Path::new("/var/lib/zdr/alice/password.cred"));
        assert_eq!(argv[0], "systemd-creds");
        assert_eq!(argv[1], "decrypt");
        assert!(argv.contains(&"--name=zdr-password".to_string()));
        assert!(argv.contains(&"--newline=no".to_string()));
        assert_eq!(argv[argv.len() - 2], "/var/lib/zdr/alice/password.cred");
        assert_eq!(argv[argv.len() - 1], "-");
    }

    #[test]
    fn seal_via_fake_runner_lands_0600_blob() {
        let dir = temp_dir("seal");
        let out = dir.join("alice").join("password.cred");
        let fake = Arc::new(FakeRunner::new(Vec::new(), true));
        let sealer = PasswordSealer::with_runner("7".to_string(), fake.clone());
        sealer
            .seal(&SecretBytes::from_slice(SECRET), &out)
            .expect("seal");
        assert_eq!(
            std::fs::read(&out).expect("blob"),
            b"fake sealed blob".to_vec()
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&out).expect("meta").permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        let calls = fake.calls.lock().expect("calls");
        assert_eq!(calls.len(), 1);
        assert!(calls[0].stdin_present, "password must be fed on stdin");
        assert_eq!(calls[0].stdin_len, SECRET.len());
        let secret_text = String::from_utf8_lossy(SECRET).into_owned();
        assert!(calls[0].argv.iter().all(|a| !a.contains(&secret_text)));
        drop(calls);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn seal_failure_error_never_echoes_stderr_or_password() {
        let dir = temp_dir("sealfail");
        let out = dir.join("alice").join("password.cred");
        let mut fake = FakeRunner::new(Vec::new(), false);
        fake.stderr = b"boom SECRET-MARKER correct horse".to_vec();
        let sealer = PasswordSealer::with_runner("7".to_string(), Arc::new(fake));
        let err = sealer
            .seal(&SecretBytes::from_slice(SECRET), &out)
            .expect_err("seal must fail");
        let text = err.to_string();
        assert!(!text.contains("SECRET-MARKER"), "stderr leaked: {text}");
        assert!(!text.contains("correct horse"), "password leaked: {text}");
        assert!(!out.exists(), "failed seal must not leave a blob");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unseal_via_fake_runner_returns_secret_without_stdin() {
        let fake = Arc::new(FakeRunner::new(SECRET.to_vec(), true));
        let sealer = PasswordSealer::with_runner("7".to_string(), fake.clone());
        let secret = sealer
            .unseal(Path::new("/var/lib/zdr/alice/password.cred"))
            .expect("unseal");
        assert_eq!(secret.as_slice(), SECRET);
        let calls = fake.calls.lock().expect("calls");
        assert_eq!(calls.len(), 1);
        assert!(!calls[0].stdin_present, "decrypt takes no stdin");
        drop(calls);
    }

    #[test]
    fn runner_errors_map_through_sealer() {
        let mut fake = FakeRunner::new(Vec::new(), true);
        fake.error = Some(SealError::Timeout);
        let sealer = PasswordSealer::with_runner("7".to_string(), Arc::new(fake));
        assert_eq!(
            sealer.unseal(Path::new("/x/password.cred")).err(),
            Some(SealError::Timeout)
        );
        // Empty passwords are refused before any subprocess runs.
        let dir = temp_dir("empty");
        let sealer = PasswordSealer::with_runner(
            "7".to_string(),
            Arc::new(FakeRunner::new(Vec::new(), true)),
        );
        assert!(sealer
            .seal(&SecretBytes::new(Vec::new()), &dir.join("password.cred"))
            .is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn has_sealed_password_is_existence_only() {
        let dir = temp_dir("has");
        assert!(!has_sealed_password(&dir, "alice"));
        assert!(!has_sealed_password(&dir, "../etc"));
        let user_dir = dir.join("alice");
        std::fs::create_dir_all(&user_dir).expect("user dir");
        std::fs::write(user_dir.join("password.cred"), b"blob").expect("blob");
        assert!(has_sealed_password(&dir, "alice"));
        assert_eq!(
            password_cred_path(&dir, "alice"),
            Some(user_dir.join("password.cred"))
        );
        assert_eq!(password_cred_path(&dir, "../etc"), None);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
