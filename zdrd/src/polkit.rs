//! Polkit authorization for GUI self-enrollment.
//!
//! A non-root caller may enroll *themselves* only after the polkit
//! authority approves action `org.zdr.Authenticator.Enroll` for their
//! bus connection (packaging/polkit/org.zdr.Authenticator.policy).
//! The decision logic ([`authorize_begin`]) is pure and takes the
//! polkit verdict through the [`PolkitChecker`] seam, so unit tests
//! inject allow/deny without a bus. The real verdict comes from
//! [`check_enroll_on_bus`], an async `CheckAuthorization` call on the
//! daemon's system-bus connection; any error or `is_authorized=false`
//! is a denial (fail closed).

use crate::consent::Caller;
use std::collections::HashMap;
use zbus::zvariant::{OwnedValue, Value};
use zbus::Connection;

pub const AUTHORITY_BUS_NAME: &str = "org.freedesktop.PolicyKit1";
pub const AUTHORITY_OBJECT_PATH: &str = "/org/freedesktop/PolicyKit1/Authority";
pub const AUTHORITY_INTERFACE: &str = "org.freedesktop.PolicyKit1.Authority";
pub const ACTION_ID: &str = "org.zdr.Authenticator.Enroll";
/// polkit `AuthorizationFlags`: AllowUserInteraction (the session
/// polkit agent may prompt the user to authenticate).
pub const FLAG_ALLOW_USER_INTERACTION: u32 = 1;

/// Seam for the polkit verdict. Implementations must fail closed:
/// any error is `false`.
pub trait PolkitChecker {
    fn check_enroll(&self, caller_name: &str) -> bool;
}

/// Checker carrying a verdict already obtained elsewhere. The D-Bus
/// layer fetches the real verdict asynchronously (see
/// [`check_enroll_on_bus`]) and adapts it through this type so the
/// pure [`authorize_begin`] decision is the only policy logic.
pub struct FixedPolkit(pub bool);

impl PolkitChecker for FixedPolkit {
    fn check_enroll(&self, _caller_name: &str) -> bool {
        self.0
    }
}

/// `BeginEnroll` authorization for one caller/target pair:
///
/// - uid 0 is always allowed (pre-GUI root flow; checker untouched);
/// - a non-root caller whose uid is not the target user's uid (or
///   whose target user does not exist) is denied, and the checker is
///   never consulted — non-root callers may never enroll someone else;
/// - a non-root caller enrolling themselves is allowed iff the
///   checker (polkit) approves.
pub fn authorize_begin(
    caller: &Caller,
    target_uid: Option<u32>,
    checker: &dyn PolkitChecker,
) -> Result<(), AccessDenied> {
    if caller.uid == 0 {
        return Ok(());
    }
    if target_uid != Some(caller.uid) {
        return Err(AccessDenied);
    }
    if checker.check_enroll(&caller.sender) {
        Ok(())
    } else {
        Err(AccessDenied)
    }
}

/// Marker error: the caller may not begin this enrollment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccessDenied;

impl std::fmt::Display for AccessDenied {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("caller is not authorized to enroll this user")
    }
}

impl std::error::Error for AccessDenied {}

/// The full `CheckAuthorization` argument tuple:
/// `(subject, action_id, details, flags, cancellation_id)` where the
/// subject is `(kind, details)` = `("system-bus-name", {"name": ..})`,
/// i.e. zvariant signature `((sa{sv})sa{sv}us)`.
pub type CheckAuthorizationArgs<'a> = (
    (&'a str, HashMap<&'a str, Value<'a>>),
    &'a str,
    HashMap<&'a str, Value<'a>>,
    u32,
    &'a str,
);

/// Build the `CheckAuthorization` arguments for `caller_name` (the
/// caller's unique bus name, taken from the message header by the
/// service layer — never from client-supplied data).
pub fn check_authorization_args(caller_name: &str) -> CheckAuthorizationArgs<'_> {
    let mut subject_details = HashMap::new();
    subject_details.insert("name", Value::from(caller_name));
    (
        ("system-bus-name", subject_details),
        ACTION_ID,
        HashMap::new(),
        FLAG_ALLOW_USER_INTERACTION,
        "",
    )
}

/// Ask the polkit authority, over the daemon's system-bus connection,
/// whether `caller_name` may perform [`ACTION_ID`]. Returns `false`
/// on `is_authorized=false` and on any bus/polkit error.
pub async fn check_enroll_on_bus(conn: &Connection, caller_name: &str) -> bool {
    let proxy = match zbus::Proxy::new(
        conn,
        AUTHORITY_BUS_NAME,
        AUTHORITY_OBJECT_PATH,
        AUTHORITY_INTERFACE,
    )
    .await
    {
        Ok(p) => p,
        Err(e) => {
            eprintln!("zdrd: polkit proxy failed for {caller_name}: {e}");
            return false;
        }
    };
    let args = check_authorization_args(caller_name);
    match proxy
        .call::<_, _, (bool, bool, HashMap<String, OwnedValue>)>("CheckAuthorization", &args)
        .await
    {
        Ok((is_authorized, _is_challenge, _details)) => is_authorized,
        Err(e) => {
            eprintln!("zdrd: polkit CheckAuthorization failed for {caller_name}: {e}");
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    struct CountingChecker {
        verdict: bool,
        calls: Cell<usize>,
        seen: std::cell::RefCell<String>,
    }

    impl CountingChecker {
        fn new(verdict: bool) -> Self {
            CountingChecker {
                verdict,
                calls: Cell::new(0),
                seen: std::cell::RefCell::new(String::new()),
            }
        }
    }

    impl PolkitChecker for CountingChecker {
        fn check_enroll(&self, caller_name: &str) -> bool {
            self.calls.set(self.calls.get() + 1);
            *self.seen.borrow_mut() = caller_name.to_string();
            self.verdict
        }
    }

    fn caller(sender: &str, uid: u32) -> Caller {
        Caller {
            sender: sender.to_string(),
            uid,
        }
    }

    #[test]
    fn root_begin_needs_no_polkit() {
        let checker = CountingChecker::new(false);
        assert_eq!(
            authorize_begin(&caller(":1.7", 0), Some(1000), &checker),
            Ok(())
        );
        assert_eq!(checker.calls.get(), 0, "root must not consult polkit");
    }

    #[test]
    fn non_root_other_user_rejected_without_polkit_call() {
        let checker = CountingChecker::new(true);
        assert_eq!(
            authorize_begin(&caller(":1.42", 1000), Some(1001), &checker),
            Err(AccessDenied)
        );
        // Unknown target user is likewise not the caller's own uid.
        assert_eq!(
            authorize_begin(&caller(":1.42", 1000), None, &checker),
            Err(AccessDenied)
        );
        assert_eq!(
            checker.calls.get(),
            0,
            "polkit must not be consulted for another user's enrollment"
        );
    }

    #[test]
    fn non_root_self_begin_follows_polkit_verdict() {
        let allow = CountingChecker::new(true);
        assert_eq!(
            authorize_begin(&caller(":1.42", 1000), Some(1000), &allow),
            Ok(())
        );
        assert_eq!(allow.calls.get(), 1);
        assert_eq!(allow.seen.borrow().as_str(), ":1.42");

        let deny = CountingChecker::new(false);
        assert_eq!(
            authorize_begin(&caller(":1.42", 1000), Some(1000), &deny),
            Err(AccessDenied)
        );
        assert_eq!(deny.calls.get(), 1);
    }

    #[test]
    fn check_authorization_args_encoding() {
        let args = check_authorization_args(":1.42");
        // Exact zvariant signature of the whole argument tuple.
        use zbus::zvariant::DynamicType;
        assert_eq!(args.signature().to_string(), "((sa{sv})sa{sv}us)");
        let (subject, action_id, details, flags, cancellation_id) = &args;
        assert_eq!(subject.0, "system-bus-name");
        assert_eq!(subject.1.len(), 1);
        match subject.1.get("name") {
            Some(Value::Str(name)) => assert_eq!(name.as_str(), ":1.42"),
            other => panic!("subject name must be a string variant, got {other:?}"),
        }
        assert_eq!(*action_id, ACTION_ID);
        assert!(details.is_empty());
        assert_eq!(*flags, FLAG_ALLOW_USER_INTERACTION);
        assert_eq!(*cancellation_id, "");
        // The tuple must actually serialize under the D-Bus encoding.
        let ctxt = zbus::zvariant::serialized::Context::new_dbus(zbus::zvariant::Endian::Little, 0);
        let encoded = zbus::zvariant::to_bytes(ctxt, &args).expect("serialize args");
        assert!(!encoded.is_empty());
    }
}
