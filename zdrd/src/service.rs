//! D-Bus service: `org.zdr.Authenticator` at `/org/zdr/Authenticator`.
//!
//! Wire contract (frozen; the agent and PAM lanes build against this):
//! - `RegisterAgent() -> ()`
//! - `BeginAuth(user, service, tty, label) -> (request_id, channel)`,
//!   channel in {"agent", "terminal"}
//! - `Respond(request_id, approved) -> ()`
//! - `AwaitConsent(request_id) -> outcome` in {"approved","denied","expired"}
//! - `CaptureVerify(request_id) -> (matched, reason)`, reason in
//!   {"match","nomatch","noface-ir","noface-rgb","not-approved","expired",
//!    "camera","engine"}
//! - `Cancel(request_id) -> ()`
//! - `BeginEnroll(user) -> (enroll_id)`, `EnrollCapture(enroll_id) ->
//!   (state, captured, needed, kind)`, `FinishEnroll(enroll_id) ->
//!   (stored)`, `CancelEnroll(enroll_id) -> ()` — root only (Step 11)
//! - `ServerInfo() -> (version, require_ir)` — read-only, any uid,
//!   no side effects (Step 14; the only contract addition)
//! - `EnrollPassword(user, password) -> ()` — root only (Step 15);
//!   TPM-seals the password to `<auth-dir>/<user>/password.cred`
//! - `HasSealedPassword(user) -> (has)` — any uid, existence only
//! - `CaptureVerifyAuthtok(request_id) -> (matched, reason,
//!   password)` — root only; like `CaptureVerify`, plus the sealed
//!   password on a match (empty when none is sealed), Step 15
//! - Signal `AuthRequested(request_id, user, service, tty, label)`
//! - Signal `AuthFeedback(request_id, kind, message)` — emitted during
//!   CaptureVerify and enrollment captures; for enrollment the first
//!   argument carries the enroll_id. kind in {"capturing","no-face",
//!   "multiple-faces","too-dark","too-bright","duplicate-pose",
//!   "matched","not-matched","stored","error"}
//!
//! Authorization: BeginAuth/AwaitConsent/CaptureVerify/Cancel accept uid 0
//! callers only. Respond accepts uid 0, or the registered agent connection
//! whose uid resolves to the request's user. Capture happens only inside
//! CaptureVerify, after approval, and consumes the request exactly once.

use crate::consent::{Caller, Consent, ConsentError};
use crate::enroll::{EnrollError, Enrollments};
use crate::feedback::FeedbackKind;
use crate::seal::{PasswordSealer, SecretBytes};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use zbus::message::Header;
use zbus::object_server::SignalEmitter;
use zbus::{interface, Connection, DBusError};

/// Hard timeout around capture + inference in CaptureVerify.
pub const CAPTURE_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Debug, DBusError)]
#[zbus(prefix = "org.zdr.Authenticator.Error", impl_display = true)]
pub enum AuthError {
    #[zbus(error)]
    ZBus(zbus::Error),
    /// One request is already pending for the user (contract: name is
    /// `org.zdr.Authenticator.Error.Busy`).
    Busy(String),
    /// BeginAuth during the post-denial cooldown.
    Cooldown(String),
    AccessDenied(String),
    Failed(String),
    InvalidArgs(String),
}

impl From<ConsentError> for AuthError {
    fn from(e: ConsentError) -> Self {
        match e {
            ConsentError::Busy => AuthError::Busy(e.to_string()),
            ConsentError::Cooldown => AuthError::Cooldown(e.to_string()),
            ConsentError::AccessDenied => AuthError::AccessDenied(e.to_string()),
            ConsentError::Unknown => AuthError::Failed(e.to_string()),
            ConsentError::Expired => AuthError::Failed(e.to_string()),
            ConsentError::NotApproved => AuthError::Failed(e.to_string()),
        }
    }
}

/// Blocking face verification, run via `spawn_blocking` under a timeout.
/// Returns `(matched, reason)` using the contract reason strings.
/// Implementations must fail closed: any internal failure is a reason
/// string, never a panic.
pub trait Verifier: Send + Sync {
    fn verify(&self, user: &str) -> (bool, String);

    /// Whether this verifier requires the IR camera. `false` means
    /// RGB-only mode. Reported read-only via `ServerInfo`.
    fn require_ir(&self) -> bool {
        true
    }

    /// Verify with streamed feedback: `capturing` before capture, then
    /// exactly one terminal kind matching the `(matched, reason)` result.
    /// The default threads the callback around `verify`; implementors
    /// may emit finer-grained kinds internally as long as the terminal
    /// kind still comes from `FeedbackKind::terminal_for_verify`.
    fn verify_with_feedback(&self, user: &str, feedback: &dyn Fn(FeedbackKind)) -> (bool, String) {
        feedback(FeedbackKind::Capturing);
        let (matched, reason) = self.verify(user);
        feedback(FeedbackKind::terminal_for_verify(matched, &reason));
        (matched, reason)
    }

    /// One enrollment capture against `existing` session embeddings.
    /// Returns the feedback kind and, on success, the new embedding.
    /// Default: unsupported (fail closed with `error`).
    fn capture_for_enroll(&self, _existing: &[Vec<f32>]) -> (FeedbackKind, Option<Vec<f32>>) {
        (FeedbackKind::Error, None)
    }

    /// Persist a finished enrollment and reload in-memory templates.
    /// Returns the number stored. Default: unsupported.
    fn finish_enroll_store(&self, _user: &str, _embeddings: &[Vec<f32>]) -> Result<usize, String> {
        Err("enrollment not supported by this verifier".to_string())
    }
}

pub struct Authenticator {
    consent: Arc<Mutex<Consent>>,
    enrollments: Arc<Mutex<Enrollments>>,
    verifier: Arc<dyn Verifier>,
    auth_dir: PathBuf,
    sealer: Arc<PasswordSealer>,
}

impl Authenticator {
    pub fn with_sealer(
        verifier: Arc<dyn Verifier>,
        auth_dir: PathBuf,
        sealer: Arc<PasswordSealer>,
    ) -> Self {
        Authenticator {
            consent: Arc::new(Mutex::new(Consent::new())),
            enrollments: Arc::new(Mutex::new(Enrollments::new())),
            verifier,
            auth_dir,
            sealer,
        }
    }

    /// Consume an approved request exactly once, mapping the
    /// not-approved / expired / unknown cases onto the contract's
    /// `(matched, reason)` results shared by both capture methods.
    /// `Ok(Err(result))` is a contract result, `Err` a bus error.
    fn take_verify_user(
        &self,
        request_id: &str,
    ) -> Result<std::result::Result<String, (bool, String)>, AuthError> {
        match self
            .lock_consent()?
            .take_for_verify(request_id, Instant::now())
        {
            Ok(req) => Ok(Ok(req.user)),
            Err(ConsentError::NotApproved) => Ok(Err((false, "not-approved".to_string()))),
            Err(ConsentError::Expired) | Err(ConsentError::Unknown) => {
                Ok(Err((false, "expired".to_string())))
            }
            Err(e) => Err(e.into()),
        }
    }

    fn lock_enrollments(&self) -> Result<std::sync::MutexGuard<'_, Enrollments>, AuthError> {
        self.enrollments
            .lock()
            .map_err(|_| AuthError::Failed("enrollment state poisoned".into()))
    }

    fn lock_consent(&self) -> Result<std::sync::MutexGuard<'_, Consent>, AuthError> {
        self.consent
            .lock()
            .map_err(|_| AuthError::Failed("consent state poisoned".into()))
    }
}

/// Resolve the uid of the caller that sent this message, via the bus
/// daemon's GetConnectionUnixUser (the sender unique name comes from the
/// message header; credentials come from the daemon, not the client).
async fn caller_uid(conn: &Connection, header: &Header<'_>) -> Result<u32, AuthError> {
    let sender = header
        .sender()
        .ok_or_else(|| AuthError::AccessDenied("message has no sender".into()))?;
    let proxy = zbus::fdo::DBusProxy::new(conn)
        .await
        .map_err(|e| AuthError::Failed(format!("bus proxy: {e}")))?;
    proxy
        .get_connection_unix_user(sender.clone().into())
        .await
        .map_err(|e| AuthError::Failed(format!("sender credentials: {e}")))
}

async fn require_root(conn: &Connection, header: &Header<'_>) -> Result<Caller, AuthError> {
    let uid = caller_uid(conn, header).await?;
    let sender = header
        .sender()
        .map(|s| s.as_str().to_string())
        .unwrap_or_default();
    if uid != 0 {
        return Err(AuthError::AccessDenied(format!(
            "caller uid {uid} is not root"
        )));
    }
    Ok(Caller { sender, uid })
}

async fn caller(conn: &Connection, header: &Header<'_>) -> Result<Caller, AuthError> {
    let uid = caller_uid(conn, header).await?;
    let sender = header
        .sender()
        .map(|s| s.as_str().to_string())
        .unwrap_or_default();
    Ok(Caller { sender, uid })
}

/// Look up a user's uid in /etc/passwd (service-layer helper; the consent
/// state machine itself stays free of system databases).
fn uid_for_user(user: &str) -> Option<u32> {
    if user.is_empty() || user.contains(['/', '\0', ':']) || user == "." || user == ".." {
        return None;
    }
    let passwd = std::fs::read_to_string("/etc/passwd").ok()?;
    for line in passwd.lines() {
        let mut fields = line.split(':');
        if fields.next() == Some(user) {
            let _passwd = fields.next()?;
            return fields.next()?.parse::<u32>().ok();
        }
    }
    None
}

/// Random 128-bit request id, hex-encoded (32 chars).
fn new_request_id() -> Result<String, AuthError> {
    let mut bytes = [0u8; 16];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut bytes))
        .map_err(|e| AuthError::Failed(format!("reading /dev/urandom: {e}")))?;
    let mut id = String::with_capacity(32);
    for b in bytes {
        id.push_str(&format!("{b:02x}"));
    }
    Ok(id)
}

/// Emit one AuthFeedback signal; failures are logged, never fatal
/// (feedback is advisory — the (matched, reason) result decides).
async fn emit_feedback(emitter: &SignalEmitter<'_>, request_id: &str, kind: FeedbackKind) {
    if let Err(e) =
        Authenticator::auth_feedback(emitter, request_id, kind.as_str(), kind.message()).await
    {
        eprintln!("zdrd: AuthFeedback emit failed for {request_id}: {e}");
    }
}

/// CaptureVerifyAuthtok core, run on the worker thread: verify once,
/// and only on a match touch the sealed blob. After a successful
/// unseal the match is verified a *second* time against the template
/// store (defence in depth: the released bytes are the user's real
/// password, so one capture must not be enough to extract them)
/// before the password leaves the daemon. Every failure path returns
/// an empty password; the unsealed SecretBytes is dropped (zeroized)
/// here whenever it is not returned. Logs carry user + request id
/// only, never contents.
fn verify_and_release(
    verifier: &dyn Verifier,
    user: &str,
    request_id: &str,
    sealer: &PasswordSealer,
    auth_dir: &Path,
    feedback: &dyn Fn(FeedbackKind),
) -> (bool, String, Option<SecretBytes>) {
    let (matched, reason) = verifier.verify_with_feedback(user, feedback);
    if !matched {
        return (matched, reason, None);
    }
    let path = match crate::seal::password_cred_path(auth_dir, user) {
        Some(p) if p.is_file() => p,
        // Matched but nothing sealed: not an error, empty password.
        _ => return (matched, reason, None),
    };
    let secret = match sealer.unseal(&path) {
        Ok(secret) => secret,
        Err(e) => {
            eprintln!("zdrd: CaptureVerifyAuthtok unseal failed user={user} id={request_id}: {e}");
            return (false, "engine".to_string(), None);
        }
    };
    let (matched2, reason2) = verifier.verify_with_feedback(user, feedback);
    if !matched2 {
        eprintln!(
            "zdrd: CaptureVerifyAuthtok second verify failed user={user} id={request_id} reason={reason2}"
        );
        // `secret` drops here and is zeroized, never returned.
        return (false, reason2, None);
    }
    eprintln!(
        "zdrd: CaptureVerifyAuthtok unseal ok, second verify matched user={user} id={request_id}"
    );
    (true, reason2, Some(secret))
}

#[interface(name = "org.zdr.Authenticator")]
impl Authenticator {
    /// Read-only daemon info: callable by any uid, no side effects,
    /// no authorization check by design (Step 14 contract addition).
    #[zbus(out_args("version", "require_ir"))]
    async fn server_info(&self) -> (String, bool) {
        (
            env!("CARGO_PKG_VERSION").to_string(),
            self.verifier.require_ir(),
        )
    }

    async fn register_agent(
        &self,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] conn: &Connection,
    ) -> Result<(), AuthError> {
        let who = caller(conn, &header).await?;
        self.lock_consent()?.register_agent(&who.sender, who.uid);
        eprintln!(
            "zdrd: agent registered sender={} uid={}",
            who.sender, who.uid
        );
        Ok(())
    }

    #[zbus(out_args("request_id", "channel"))]
    async fn begin_auth(
        &self,
        user: &str,
        service: &str,
        tty: &str,
        label: &str,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] conn: &Connection,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
    ) -> Result<(String, String), AuthError> {
        require_root(conn, &header).await?;
        let request_id = new_request_id()?;
        let user_uid = uid_for_user(user);
        let channel = self.lock_consent()?.begin(
            &request_id,
            user,
            user_uid,
            service,
            tty,
            label,
            Instant::now(),
        )?;
        eprintln!(
            "zdrd: BeginAuth user={user} service={service} tty={tty} channel={} id={request_id}",
            channel.as_str()
        );
        if let Err(e) = Self::auth_requested(&emitter, &request_id, user, service, tty, label).await
        {
            eprintln!("zdrd: AuthRequested emit failed for {request_id}: {e}");
        }
        Ok((request_id, channel.as_str().to_string()))
    }

    async fn respond(
        &self,
        request_id: &str,
        approved: bool,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] conn: &Connection,
    ) -> Result<(), AuthError> {
        let who = caller(conn, &header).await?;
        self.lock_consent()?
            .respond(request_id, approved, &who, Instant::now())?;
        eprintln!(
            "zdrd: Respond id={request_id} approved={approved} uid={}",
            who.uid
        );
        Ok(())
    }

    async fn await_consent(
        &self,
        request_id: &str,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] conn: &Connection,
    ) -> Result<String, AuthError> {
        require_root(conn, &header).await?;
        // Poll the pure state machine until a decision or the 30 s expiry
        // (outcome() itself performs the expiry transition).
        loop {
            let outcome = self.lock_consent()?.outcome(request_id, Instant::now());
            match outcome {
                Ok(Some(outcome)) => return Ok(outcome.as_str().to_string()),
                // NOTE: no tokio::time here. zbus runs this handler on its
                // own executor thread without a Tokio reactor context;
                // tokio::time::sleep panics there (seen live 2026-10-14).
                // async-io's Timer runs on its own reactor and works.
                Ok(None) => {
                    async_io::Timer::after(Duration::from_millis(50)).await;
                }
                Err(ConsentError::Unknown) => return Ok("expired".to_string()),
                Err(e) => return Err(e.into()),
            }
        }
    }

    #[zbus(out_args("matched", "reason"))]
    async fn capture_verify(
        &self,
        request_id: &str,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] conn: &Connection,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
    ) -> Result<(bool, String), AuthError> {
        require_root(conn, &header).await?;
        // Consume the approved request exactly once, before any capture.
        let user = match self.take_verify_user(request_id)? {
            Ok(user) => user,
            Err(result) => return Ok(result),
        };
        // Capture + inference is blocking (cameras, ONNX): run it on a
        // plain thread and poll for the result with a hard deadline. No
        // tokio APIs here either (see AwaitConsent note): tokio::task and
        // tokio::time panic on the zbus executor thread. A thread that
        // outlives the deadline cannot be killed; it holds the cameras
        // until it returns, and the next attempt then fails closed.
        // Feedback and the result share one channel so signals are
        // emitted in order and the terminal kind is never lost behind
        // the return value.
        enum WorkerMsg {
            Feedback(FeedbackKind),
            Done((bool, String)),
        }
        let verifier = Arc::clone(&self.verifier);
        let capture_user = user.clone();
        let (tx, rx) = std::sync::mpsc::channel::<WorkerMsg>();
        let fb_tx = tx.clone();
        let spawned = std::thread::Builder::new()
            .name("zdrd-capture".to_string())
            .spawn(move || {
                let feedback = |kind: FeedbackKind| {
                    let _ = fb_tx.send(WorkerMsg::Feedback(kind));
                };
                let result = verifier.verify_with_feedback(&capture_user, &feedback);
                let _ = tx.send(WorkerMsg::Done(result));
            });
        if let Err(e) = spawned {
            eprintln!("zdrd: CaptureVerify spawn failed for user={user}: {e}");
            emit_feedback(&emitter, request_id, FeedbackKind::Error).await;
            return Ok((false, "engine".to_string()));
        }
        let deadline = Instant::now() + CAPTURE_TIMEOUT;
        loop {
            match rx.try_recv() {
                Ok(WorkerMsg::Feedback(kind)) => {
                    emit_feedback(&emitter, request_id, kind).await;
                }
                Ok(WorkerMsg::Done(result)) => {
                    eprintln!(
                        "zdrd: CaptureVerify user={user} matched={} reason={}",
                        result.0, result.1
                    );
                    return Ok(result);
                }
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    eprintln!("zdrd: CaptureVerify worker stopped for user={user}");
                    emit_feedback(&emitter, request_id, FeedbackKind::Error).await;
                    return Ok((false, "engine".to_string()));
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => {}
            }
            if Instant::now() >= deadline {
                eprintln!("zdrd: CaptureVerify timed out for user={user}");
                emit_feedback(&emitter, request_id, FeedbackKind::Error).await;
                return Ok((false, "camera".to_string()));
            }
            async_io::Timer::after(Duration::from_millis(25)).await;
        }
    }

    /// Step 15: seal `password` for `user` to
    /// `<auth-dir>/<user>/password.cred`, bound to the TPM. Root
    /// only, like BeginAuth. The D-Bus layer materializes `password`
    /// as a String; it is converted into a zeroizing SecretBytes
    /// immediately and the String's buffer moves with it (into_bytes),
    /// so no extra daemon-owned copy is made. Never logged.
    async fn enroll_password(
        &self,
        user: &str,
        password: String,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] conn: &Connection,
    ) -> Result<(), AuthError> {
        require_root(conn, &header).await?;
        if !crate::templates::valid_user(user) || uid_for_user(user).is_none() {
            return Err(AuthError::InvalidArgs(format!("unknown user {user:?}")));
        }
        if password.is_empty() {
            return Err(AuthError::InvalidArgs("empty password".to_string()));
        }
        let secret = SecretBytes::new(password.into_bytes());
        let path = crate::seal::password_cred_path(&self.auth_dir, user)
            .ok_or_else(|| AuthError::InvalidArgs(format!("invalid user name {user:?}")))?;
        // systemd-creds is blocking: run it on a plain thread and poll
        // with a deadline (no tokio APIs on the zbus executor thread).
        // The runner itself enforces the 10 s cap; this deadline is a
        // backstop so the handler can never hang on a stuck child.
        let sealer = Arc::clone(&self.sealer);
        let (tx, rx) = std::sync::mpsc::channel::<Result<(), crate::seal::SealError>>();
        let spawned = std::thread::Builder::new()
            .name("zdrd-seal".to_string())
            .spawn(move || {
                let result = sealer.seal(&secret, &path);
                // `secret` drops (zeroized) when this thread ends.
                let _ = tx.send(result);
            });
        if let Err(e) = spawned {
            eprintln!("zdrd: EnrollPassword spawn failed for user={user}: {e}");
            return Err(AuthError::Failed(format!(
                "sealing password for {user}: spawn failed"
            )));
        }
        let deadline = Instant::now() + crate::seal::SEAL_TIMEOUT + Duration::from_secs(2);
        loop {
            match rx.try_recv() {
                Ok(Ok(())) => {
                    eprintln!("zdrd: EnrollPassword sealed password for user={user}");
                    return Ok(());
                }
                Ok(Err(e)) => {
                    eprintln!("zdrd: EnrollPassword seal failed for user={user}: {e}");
                    return Err(AuthError::Failed(format!(
                        "sealing password for {user}: {e}"
                    )));
                }
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    eprintln!("zdrd: EnrollPassword worker stopped for user={user}");
                    return Err(AuthError::Failed(format!(
                        "sealing password for {user}: worker stopped"
                    )));
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => {}
            }
            if Instant::now() >= deadline {
                eprintln!("zdrd: EnrollPassword timed out for user={user}");
                return Err(AuthError::Failed(format!(
                    "sealing password for {user}: timed out"
                )));
            }
            async_io::Timer::after(Duration::from_millis(25)).await;
        }
    }

    /// Step 15: whether a sealed password exists for `user`. Any uid;
    /// reveals existence only, never reads the blob.
    #[zbus(out_args("has"))]
    async fn has_sealed_password(&self, user: &str) -> bool {
        crate::seal::has_sealed_password(&self.auth_dir, user)
    }

    /// Step 15: CaptureVerify plus TPM-sealed password release.
    /// Consumes the approved request exactly once, like CaptureVerify;
    /// only after a match is the blob unsealed, and the match is then
    /// verified a second time inside the daemon (see
    /// `verify_and_release`) before any password byte is returned.
    /// The daemon-owned SecretBytes is copied into the D-Bus return
    /// value and zeroized before this handler returns.
    #[zbus(out_args("matched", "reason", "password"))]
    async fn capture_verify_authtok(
        &self,
        request_id: &str,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] conn: &Connection,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
    ) -> Result<(bool, String, Vec<u8>), AuthError> {
        require_root(conn, &header).await?;
        // Consume the approved request exactly once, before any capture.
        let user = match self.take_verify_user(request_id)? {
            Ok(user) => user,
            Err((matched, reason)) => return Ok((matched, reason, Vec::new())),
        };
        // Same worker-thread pattern as CaptureVerify (no tokio APIs
        // on the zbus executor thread). Unseal runs inside the same
        // worker after a successful match: the overall budget is the
        // 15 s capture budget plus the sealer's own 10 s cap.
        enum WorkerMsg {
            Feedback(FeedbackKind),
            Done((bool, String, Option<SecretBytes>)),
        }
        let verifier = Arc::clone(&self.verifier);
        let sealer = Arc::clone(&self.sealer);
        let auth_dir = self.auth_dir.clone();
        let capture_user = user.clone();
        let capture_id = request_id.to_string();
        let (tx, rx) = std::sync::mpsc::channel::<WorkerMsg>();
        let fb_tx = tx.clone();
        let spawned = std::thread::Builder::new()
            .name("zdrd-capture-authtok".to_string())
            .spawn(move || {
                let feedback = |kind: FeedbackKind| {
                    let _ = fb_tx.send(WorkerMsg::Feedback(kind));
                };
                let result = verify_and_release(
                    verifier.as_ref(),
                    &capture_user,
                    &capture_id,
                    &sealer,
                    &auth_dir,
                    &feedback,
                );
                let _ = tx.send(WorkerMsg::Done(result));
            });
        if let Err(e) = spawned {
            eprintln!("zdrd: CaptureVerifyAuthtok spawn failed for user={user}: {e}");
            emit_feedback(&emitter, request_id, FeedbackKind::Error).await;
            return Ok((false, "engine".to_string(), Vec::new()));
        }
        let deadline = Instant::now() + CAPTURE_TIMEOUT + crate::seal::SEAL_TIMEOUT;
        loop {
            match rx.try_recv() {
                Ok(WorkerMsg::Feedback(kind)) => {
                    emit_feedback(&emitter, request_id, kind).await;
                }
                Ok(WorkerMsg::Done((matched, reason, secret))) => {
                    // Copy into the D-Bus-owned return vector, then
                    // drop our SecretBytes so the daemon copy is
                    // zeroized before the return path completes.
                    let released = secret.is_some();
                    let password = match secret {
                        Some(secret) => {
                            let bytes = secret.as_slice().to_vec();
                            drop(secret);
                            bytes
                        }
                        None => Vec::new(),
                    };
                    eprintln!(
                        "zdrd: CaptureVerifyAuthtok user={user} id={request_id} matched={matched} reason={reason} password_released={released}"
                    );
                    return Ok((matched, reason, password));
                }
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    eprintln!("zdrd: CaptureVerifyAuthtok worker stopped for user={user}");
                    emit_feedback(&emitter, request_id, FeedbackKind::Error).await;
                    return Ok((false, "engine".to_string(), Vec::new()));
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => {}
            }
            if Instant::now() >= deadline {
                eprintln!("zdrd: CaptureVerifyAuthtok timed out for user={user}");
                emit_feedback(&emitter, request_id, FeedbackKind::Error).await;
                return Ok((false, "camera".to_string(), Vec::new()));
            }
            async_io::Timer::after(Duration::from_millis(25)).await;
        }
    }

    async fn cancel(
        &self,
        request_id: &str,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] conn: &Connection,
    ) -> Result<(), AuthError> {
        require_root(conn, &header).await?;
        let removed = self.lock_consent()?.cancel(request_id);
        eprintln!("zdrd: Cancel id={request_id} removed={removed}");
        Ok(())
    }

    #[zbus(out_args("enroll_id"))]
    async fn begin_enroll(
        &self,
        user: &str,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] conn: &Connection,
    ) -> Result<String, AuthError> {
        require_root(conn, &header).await?;
        if !crate::templates::valid_user(user) || uid_for_user(user).is_none() {
            return Err(AuthError::InvalidArgs(format!("unknown user {user:?}")));
        }
        let enroll_id = new_request_id()?;
        match self
            .lock_enrollments()?
            .begin(&enroll_id, user, Instant::now())
        {
            Ok(()) => {
                eprintln!("zdrd: BeginEnroll user={user} id={enroll_id}");
                Ok(enroll_id)
            }
            Err(EnrollError::Busy) => Err(AuthError::Busy(EnrollError::Busy.to_string())),
            Err(e) => Err(AuthError::Failed(e.to_string())),
        }
    }

    #[zbus(out_args("state", "captured", "needed", "kind"))]
    async fn enroll_capture(
        &self,
        enroll_id: &str,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] conn: &Connection,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
    ) -> Result<(String, i32, i32, String), AuthError> {
        require_root(conn, &header).await?;
        // Snapshot session state, then capture without holding the
        // enrollment lock across blocking camera work.
        let (user, existing, captured_before) = {
            let mut guard = self.lock_enrollments()?;
            let now = Instant::now();
            match (
                guard.user_for(enroll_id, now),
                guard.embeddings_for(enroll_id, now),
                guard.captured_for(enroll_id, now),
            ) {
                (Ok(u), Ok(e), Ok(c)) => (u, e, c),
                (Err(e), _, _) | (_, Err(e), _) | (_, _, Err(e)) => {
                    return Err(AuthError::Failed(e.to_string()))
                }
            }
        };
        emit_feedback(&emitter, enroll_id, FeedbackKind::Capturing).await;
        let verifier = Arc::clone(&self.verifier);
        let (tx, rx) = std::sync::mpsc::channel();
        let spawned = std::thread::Builder::new()
            .name("zdrd-enroll-capture".to_string())
            .spawn(move || {
                let _ = tx.send(verifier.capture_for_enroll(&existing));
            });
        if let Err(e) = spawned {
            eprintln!("zdrd: EnrollCapture spawn failed for user={user}: {e}");
            emit_feedback(&emitter, enroll_id, FeedbackKind::Error).await;
            return Ok((
                "rejected".to_string(),
                captured_before as i32,
                crate::enroll::NEEDED as i32,
                FeedbackKind::Error.as_str().to_string(),
            ));
        }
        let deadline = Instant::now() + CAPTURE_TIMEOUT;
        let (kind, embedding) = loop {
            match rx.try_recv() {
                Ok(result) => break result,
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    emit_feedback(&emitter, enroll_id, FeedbackKind::Error).await;
                    return Ok((
                        "rejected".to_string(),
                        captured_before as i32,
                        crate::enroll::NEEDED as i32,
                        FeedbackKind::Error.as_str().to_string(),
                    ));
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => {}
            }
            if Instant::now() >= deadline {
                eprintln!("zdrd: EnrollCapture timed out for user={user}");
                emit_feedback(&emitter, enroll_id, FeedbackKind::Error).await;
                return Ok((
                    "rejected".to_string(),
                    captured_before as i32,
                    crate::enroll::NEEDED as i32,
                    FeedbackKind::Error.as_str().to_string(),
                ));
            }
            async_io::Timer::after(Duration::from_millis(25)).await;
        };
        let attempt = self
            .lock_enrollments()?
            .apply_capture(enroll_id, Instant::now(), kind, embedding)
            .map_err(|e| AuthError::Failed(e.to_string()))?;
        emit_feedback(&emitter, enroll_id, attempt.kind).await;
        eprintln!(
            "zdrd: EnrollCapture user={user} state={} captured={}/{} kind={}",
            attempt.state.as_str(),
            attempt.captured,
            attempt.needed,
            attempt.kind.as_str()
        );
        Ok((
            attempt.state.as_str().to_string(),
            attempt.captured as i32,
            attempt.needed as i32,
            attempt.kind.as_str().to_string(),
        ))
    }

    #[zbus(out_args("stored"))]
    async fn finish_enroll(
        &self,
        enroll_id: &str,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] conn: &Connection,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
    ) -> Result<i32, AuthError> {
        require_root(conn, &header).await?;
        let (user, embeddings) = self
            .lock_enrollments()?
            .ready_snapshot(enroll_id, Instant::now())
            .map_err(|e| AuthError::Failed(e.to_string()))?;
        // Only consume the session once the store write has succeeded,
        // so a failed finish can be retried before expiry.
        let stored = self
            .verifier
            .finish_enroll_store(&user, &embeddings)
            .map_err(AuthError::Failed)?;
        self.lock_enrollments()?.cancel(enroll_id);
        emit_feedback(&emitter, enroll_id, FeedbackKind::Stored).await;
        eprintln!("zdrd: FinishEnroll user={user} stored={stored}");
        Ok(stored as i32)
    }

    async fn cancel_enroll(
        &self,
        enroll_id: &str,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] conn: &Connection,
    ) -> Result<(), AuthError> {
        require_root(conn, &header).await?;
        let removed = self.lock_enrollments()?.cancel(enroll_id);
        eprintln!("zdrd: CancelEnroll id={enroll_id} removed={removed}");
        Ok(())
    }

    #[zbus(signal)]
    async fn auth_feedback(
        signal_emitter: &SignalEmitter<'_>,
        request_id: &str,
        kind: &str,
        message: &str,
    ) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn auth_requested(
        signal_emitter: &SignalEmitter<'_>,
        request_id: &str,
        user: &str,
        service: &str,
        tty: &str,
        label: &str,
    ) -> zbus::Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    struct StubVerifier(bool, &'static str);
    impl Verifier for StubVerifier {
        fn verify(&self, _user: &str) -> (bool, String) {
            (self.0, self.1.to_string())
        }
    }

    #[test]
    fn feedback_threaded_through_verify() {
        for (stub, want_terminal) in [
            (StubVerifier(true, "match"), FeedbackKind::Matched),
            (StubVerifier(false, "nomatch"), FeedbackKind::NotMatched),
            (StubVerifier(false, "noface-ir"), FeedbackKind::NoFace),
            (StubVerifier(false, "camera"), FeedbackKind::Error),
        ] {
            let seen = RefCell::new(Vec::new());
            let cb = |k: FeedbackKind| seen.borrow_mut().push(k);
            let result = stub.verify_with_feedback("alice", &cb);
            assert_eq!(result.0, stub.0);
            assert_eq!(
                seen.into_inner(),
                vec![FeedbackKind::Capturing, want_terminal]
            );
        }
    }

    // ---- Step 15: verify_and_release (fake runner, no TPM) ----

    struct SeqVerifier {
        results: Mutex<std::collections::VecDeque<(bool, &'static str)>>,
    }
    impl SeqVerifier {
        fn new(results: &[(bool, &'static str)]) -> Self {
            SeqVerifier {
                results: Mutex::new(results.iter().copied().collect()),
            }
        }
    }
    impl Verifier for SeqVerifier {
        fn verify(&self, _user: &str) -> (bool, String) {
            match self.results.lock() {
                Ok(mut q) => q
                    .pop_front()
                    .map(|(m, r)| (m, r.to_string()))
                    .unwrap_or((false, "nomatch".to_string())),
                Err(_) => (false, "engine".to_string()),
            }
        }
    }

    struct FakeSealRunner {
        decrypt_calls: Mutex<usize>,
        stdout: Vec<u8>,
        success: bool,
    }
    impl crate::seal::CommandRunner for FakeSealRunner {
        fn run(
            &self,
            argv: &[String],
            _stdin: &[u8],
            _timeout: Duration,
        ) -> Result<crate::seal::CommandOutput, crate::seal::SealError> {
            if argv.iter().any(|a| a == "decrypt") {
                if let Ok(mut n) = self.decrypt_calls.lock() {
                    *n += 1;
                }
            }
            Ok(crate::seal::CommandOutput {
                success: self.success,
                status: Some(if self.success { 0 } else { 1 }),
                stdout: self.stdout.clone(),
                stderr: Vec::new(),
            })
        }
    }

    fn release_setup(
        tag: &str,
        with_blob: bool,
        runner: FakeSealRunner,
    ) -> (PathBuf, PasswordSealer, Arc<FakeSealRunner>) {
        let dir =
            std::env::temp_dir().join(format!("zdrd-authtok-test-{}-{}", std::process::id(), tag));
        let _ = std::fs::remove_dir_all(&dir);
        let user_dir = dir.join("alice");
        std::fs::create_dir_all(&user_dir).expect("user dir");
        if with_blob {
            std::fs::write(user_dir.join("password.cred"), b"fake blob").expect("blob");
        }
        let runner = Arc::new(runner);
        let sealer = PasswordSealer::with_runner("7".to_string(), runner.clone());
        (dir, sealer, runner)
    }

    fn no_feedback(_: FeedbackKind) {}

    #[test]
    fn authtok_releases_password_after_second_match() {
        let (dir, sealer, runner) = release_setup(
            "release",
            true,
            FakeSealRunner {
                decrypt_calls: Mutex::new(0),
                stdout: b"the-real-password".to_vec(),
                success: true,
            },
        );
        let verifier = SeqVerifier::new(&[(true, "match"), (true, "match")]);
        let (matched, reason, secret) =
            verify_and_release(&verifier, "alice", "req1", &sealer, &dir, &no_feedback);
        assert!(matched && reason == "match");
        let secret = secret.expect("password released");
        assert_eq!(secret.as_slice(), b"the-real-password");
        assert_eq!(*runner.decrypt_calls.lock().expect("calls"), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn authtok_no_blob_returns_empty_without_unseal() {
        let (dir, sealer, runner) = release_setup(
            "noblob",
            false,
            FakeSealRunner {
                decrypt_calls: Mutex::new(0),
                stdout: b"unused".to_vec(),
                success: true,
            },
        );
        let verifier = SeqVerifier::new(&[(true, "match")]);
        let (matched, reason, secret) =
            verify_and_release(&verifier, "alice", "req1", &sealer, &dir, &no_feedback);
        assert!(matched && reason == "match");
        assert!(secret.is_none());
        assert_eq!(*runner.decrypt_calls.lock().expect("calls"), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn authtok_no_unseal_attempt_when_not_matched() {
        let (dir, sealer, runner) = release_setup(
            "nomatch",
            true,
            FakeSealRunner {
                decrypt_calls: Mutex::new(0),
                stdout: b"unused".to_vec(),
                success: true,
            },
        );
        let verifier = SeqVerifier::new(&[(false, "nomatch")]);
        let (matched, reason, secret) =
            verify_and_release(&verifier, "alice", "req1", &sealer, &dir, &no_feedback);
        assert!(!matched && reason == "nomatch");
        assert!(secret.is_none());
        assert_eq!(*runner.decrypt_calls.lock().expect("calls"), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn authtok_second_verify_failure_withholds_password() {
        let (dir, sealer, runner) = release_setup(
            "secondfail",
            true,
            FakeSealRunner {
                decrypt_calls: Mutex::new(0),
                stdout: b"the-real-password".to_vec(),
                success: true,
            },
        );
        let verifier = SeqVerifier::new(&[(true, "match"), (false, "nomatch")]);
        let (matched, reason, secret) =
            verify_and_release(&verifier, "alice", "req1", &sealer, &dir, &no_feedback);
        assert!(!matched && reason == "nomatch");
        assert!(secret.is_none(), "password must be withheld and dropped");
        assert_eq!(*runner.decrypt_calls.lock().expect("calls"), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn authtok_unseal_failure_is_engine_and_empty() {
        let (dir, sealer, _runner) = release_setup(
            "unsealfail",
            true,
            FakeSealRunner {
                decrypt_calls: Mutex::new(0),
                stdout: Vec::new(),
                success: false,
            },
        );
        let verifier = SeqVerifier::new(&[(true, "match")]);
        let (matched, reason, secret) =
            verify_and_release(&verifier, "alice", "req1", &sealer, &dir, &no_feedback);
        assert!(!matched && reason == "engine");
        assert!(secret.is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
