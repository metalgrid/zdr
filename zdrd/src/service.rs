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
use crate::feedback::FeedbackKind;
use std::io::Read;
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

    /// Verify with streamed feedback: `capturing` before capture, then
    /// exactly one terminal kind matching the `(matched, reason)` result.
    /// The default threads the callback around `verify`; implementors
    /// may emit finer-grained kinds internally as long as the terminal
    /// kind still comes from `FeedbackKind::terminal_for_verify`.
    fn verify_with_feedback(
        &self,
        user: &str,
        feedback: &dyn Fn(FeedbackKind),
    ) -> (bool, String) {
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
    verifier: Arc<dyn Verifier>,
}

impl Authenticator {
    pub fn new(verifier: Arc<dyn Verifier>) -> Self {
        Authenticator {
            consent: Arc::new(Mutex::new(Consent::new())),
            verifier,
        }
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

#[interface(name = "org.zdr.Authenticator")]
impl Authenticator {
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
        let user = {
            match self
                .lock_consent()?
                .take_for_verify(request_id, Instant::now())
            {
                Ok(req) => req.user,
                Err(ConsentError::NotApproved) => return Ok((false, "not-approved".to_string())),
                Err(ConsentError::Expired) | Err(ConsentError::Unknown) => {
                    return Ok((false, "expired".to_string()))
                }
                Err(e) => return Err(e.into()),
            }
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
}
