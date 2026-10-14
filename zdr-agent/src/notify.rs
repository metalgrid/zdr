//! Desktop-notification prompt backend (freedesktop Notifications).
//!
//! Last resort in the agent's backend chain: needs no toolkit, only
//! a session bus and a notification server that supports actions.
//! One session-bus connection is opened lazily per request that
//! reaches this backend; there are no retries. Every failure path
//! here denies — the caller only ever gets `true` from an explicit
//! `approve` action on our own notification.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{mpsc, Arc};
use std::time::Duration;

use zbus::blocking::Connection;
use zbus::zvariant::Value;
use zdr_agent::prompt_fields;

#[zbus::proxy(
    interface = "org.freedesktop.Notifications",
    default_service = "org.freedesktop.Notifications",
    default_path = "/org/freedesktop/Notifications"
)]
trait Notifications {
    fn get_capabilities(&self) -> zbus::Result<Vec<String>>;
    fn notify(
        &self,
        app_name: &str,
        replaces_id: u32,
        app_icon: &str,
        summary: &str,
        body: &str,
        actions: Vec<&str>,
        hints: HashMap<&str, Value<'_>>,
        expire_timeout: i32,
    ) -> zbus::Result<u32>;

    #[zbus(signal)]
    fn notification_closed(&self, id: u32, reason: u32) -> zbus::Result<()>;

    #[zbus(signal)]
    fn action_invoked(&self, id: u32, action_key: &str) -> zbus::Result<()>;
}

enum NotifyEvent {
    Approve,
    Deny,
}

/// Show the request as a critical notification and wait (at most
/// `budget`) for the user's action. Returns `true` only on an
/// explicit approve action; backend unavailability, a server
/// without action support, closes, timeouts, and all errors deny.
pub fn prompt_via_notification(
    service: &str,
    user: &str,
    tty: &str,
    label: &str,
    budget: Duration,
) -> bool {
    let fields = prompt_fields(service, user, tty, label);
    let body = format!(
        "Service: {}\nUser: {}\nTTY: {}\nCommand: {}",
        fields[0], fields[1], fields[2], fields[3]
    );

    let connection = match Connection::session() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("zdr-agent: notify backend skipped: no session bus: {e}");
            return false;
        }
    };
    let proxy = match NotificationsProxyBlocking::new(&connection) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("zdr-agent: notify backend skipped: proxy failed: {e}");
            return false;
        }
    };

    match proxy.get_capabilities() {
        Ok(caps) if caps.iter().any(|c| c == "actions") => {}
        Ok(caps) => {
            eprintln!(
                "zdr-agent: notify backend skipped: server lacks 'actions' capability: {caps:?}"
            );
            return false;
        }
        Err(e) => {
            eprintln!("zdr-agent: notify backend skipped: GetCapabilities failed: {e}");
            return false;
        }
    }

    // Subscribe before Notify so a fast answer cannot be missed.
    // Two small threads forward matching events to one channel;
    // they exit when the receiver is dropped and a later event
    // arrives. Notification IDs are matched against the ID Notify
    // returns (published through `target_id`).
    let target_id = Arc::new(AtomicU32::new(0));
    let (sender, receiver) = mpsc::channel::<NotifyEvent>();

    let mut closed_stream = match proxy.receive_notification_closed() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("zdr-agent: notify backend skipped: cannot watch NotificationClosed: {e}");
            return false;
        }
    };
    let mut action_stream = match proxy.receive_action_invoked() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("zdr-agent: notify backend skipped: cannot watch ActionInvoked: {e}");
            return false;
        }
    };

    {
        let sender = sender.clone();
        let target_id = Arc::clone(&target_id);
        std::thread::spawn(move || {
            while let Some(signal) = closed_stream.next() {
                let Ok(args) = signal.args() else { continue };
                if *args.id() == target_id.load(Ordering::SeqCst)
                    && sender.send(NotifyEvent::Deny).is_err()
                {
                    break;
                }
            }
        });
    }
    {
        let target_id = Arc::clone(&target_id);
        std::thread::spawn(move || {
            while let Some(signal) = action_stream.next() {
                let Ok(args) = signal.args() else { continue };
                if *args.id() != target_id.load(Ordering::SeqCst) {
                    continue;
                }
                let event = if *args.action_key() == "approve" {
                    NotifyEvent::Approve
                } else {
                    NotifyEvent::Deny
                };
                if sender.send(event).is_err() {
                    break;
                }
            }
        });
    }

    let mut hints: HashMap<&str, Value<'_>> = HashMap::new();
    hints.insert("urgency", Value::U8(2)); // critical

    let notification_id = match proxy.notify(
        "zdr",
        0,
        "",
        "Face authentication requested",
        &body,
        vec!["approve", "Approve and scan", "deny", "Deny"],
        hints,
        30_000,
    ) {
        Ok(id) => id,
        Err(e) => {
            eprintln!("zdr-agent: notify backend failed: Notify failed: {e}; denying");
            return false;
        }
    };
    target_id.store(notification_id, Ordering::SeqCst);
    eprintln!("zdr-agent: notify backend: notification {notification_id} shown; waiting for action");

    match receiver.recv_timeout(budget) {
        Ok(NotifyEvent::Approve) => {
            eprintln!("zdr-agent: notify backend: user approved");
            true
        }
        Ok(NotifyEvent::Deny) => {
            eprintln!("zdr-agent: notify backend: denied/closed by user");
            false
        }
        Err(mpsc::RecvTimeoutError::Timeout) => {
            eprintln!("zdr-agent: notify backend: timed out waiting for action; denying");
            false
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            eprintln!("zdr-agent: notify backend: event watchers ended; denying");
            false
        }
    }
}
