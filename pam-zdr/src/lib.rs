extern crate pam;
extern crate rand;

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
