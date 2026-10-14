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
//! - Signal `AuthRequested(request_id, user, service, tty, label)`
//!
//! Authorization: BeginAuth/AwaitConsent/CaptureVerify/Cancel accept uid 0
//! callers only. Respond accepts uid 0, or the registered agent connection
//! whose uid resolves to the request's user. Capture happens only inside
//! CaptureVerify, after approval, and consumes the request exactly once.

use crate::consent::{Caller, Consent, ConsentError};
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
}

/// Verifier used until the real engine is wired in; fails closed.
pub struct UnavailableVerifier;

impl Verifier for UnavailableVerifier {
    fn verify(&self, _user: &str) -> (bool, String) {
        (false, "engine".to_string())
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
    if user.is_empty()
        || user.contains(['/', '\0', ':'])
        || user == "."
        || user == ".."
    {
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
        eprintln!("zdrd: Respond id={request_id} approved={approved} uid={}", who.uid);
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
                Ok(None) => tokio::time::sleep(Duration::from_millis(50)).await,
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
    ) -> Result<(bool, String), AuthError> {
        require_root(conn, &header).await?;
        // Consume the approved request exactly once, before any capture.
        let user = {
            match self
                .lock_consent()?
                .take_for_verify(request_id, Instant::now())
            {
                Ok(req) => req.user,
                Err(ConsentError::NotApproved) => {
                    return Ok((false, "not-approved".to_string()))
                }
                Err(ConsentError::Expired) | Err(ConsentError::Unknown) => {
                    return Ok((false, "expired".to_string()))
                }
                Err(e) => return Err(e.into()),
            }
        };
        // Capture + inference is blocking (cameras, ONNX): keep it off the
        // async runtime and bound it with a hard timeout. No capture of any
        // kind happens before this point.
        let verifier = Arc::clone(&self.verifier);
        let capture_user = user.clone();
        let capture = tokio::task::spawn_blocking(move || verifier.verify(&capture_user));
        match tokio::time::timeout(CAPTURE_TIMEOUT, capture).await {
            Ok(Ok(result)) => {
                eprintln!(
                    "zdrd: CaptureVerify user={user} matched={} reason={}",
                    result.0, result.1
                );
                Ok(result)
            }
            Ok(Err(e)) => {
                eprintln!("zdrd: CaptureVerify worker failed for user={user}: {e}");
                Ok((false, "engine".to_string()))
            }
            Err(_) => {
                eprintln!("zdrd: CaptureVerify timed out for user={user}");
                Ok((false, "camera".to_string()))
            }
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
    async fn auth_requested(
        signal_emitter: &SignalEmitter<'_>,
        request_id: &str,
        user: &str,
        service: &str,
        tty: &str,
        label: &str,
    ) -> zbus::Result<()>;
}
