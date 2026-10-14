//! `zdrctl` — enrollment / template administration for zdrd.
//!
//! Deliberately free of camera and ONNX code: `enroll` drives the
//! daemon over the system bus (zbus blocking API, same zbus 5 crate
//! the daemon uses; its blocking API is a default feature, so no
//! runtime or feature changes were needed), while `list`/`remove`
//! operate on `<auth-dir>/<user>/templates.bin` locally.

use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};

const DEFAULT_AUTH_DIR: &str = "/var/lib/zdr";
const POSES: [&str; 5] = [
    "Look straight at the camera",
    "Turn your head slightly to the left",
    "Turn your head slightly to the right",
    "Tilt your head slightly up",
    "Tilt your head slightly down",
];

fn main() {
    std::process::exit(run());
}

fn run() -> i32 {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (cmd, rest) = match args.split_first() {
        Some((c, r)) => (c.as_str(), r),
        None => {
            print_usage();
            return 2;
        }
    };
    let result = match cmd {
        "enroll" => cmd_enroll(rest),
        "list" => cmd_list(rest),
        "remove" => cmd_remove(rest),
        "test" => cmd_test(rest),
        "-h" | "--help" | "help" => {
            print_usage();
            Ok(())
        }
        other => {
            eprintln!("zdrctl: unknown subcommand {other:?}");
            print_usage();
            Err("unknown subcommand".to_string())
        }
    };
    match result {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("zdrctl: {e}");
            1
        }
    }
}

fn print_usage() {
    eprintln!(
        "usage:\n  zdrctl enroll [user]          guided 5-capture enrollment (run with sudo)\n  \
         zdrctl list [--auth-dir DIR]  per-user template counts\n  \
         zdrctl remove <user> [--auth-dir DIR]\n  \
         zdrctl test <user>            how to test an enrollment"
    );
}

/// Effective uid from /proc/self/status (`Uid: real effective saved fs`).
/// Std-only; no libc dependency needed for this.
fn effective_uid() -> Option<u32> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            return rest.split_whitespace().nth(1).and_then(|s| s.parse().ok());
        }
    }
    None
}

fn valid_user(user: &str) -> bool {
    !user.is_empty() && user != "." && user != ".." && !user.contains(['/', '\\', '\0'])
}

/// Split positional args from `--auth-dir DIR`.
fn parse_auth_dir(args: &[String]) -> Result<(Vec<String>, PathBuf), String> {
    let mut positional = Vec::new();
    let mut auth_dir = PathBuf::from(DEFAULT_AUTH_DIR);
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--auth-dir" {
            let value = args
                .get(i + 1)
                .ok_or_else(|| "--auth-dir needs a directory argument".to_string())?;
            auth_dir = PathBuf::from(value);
            i += 2;
        } else {
            positional.push(args[i].clone());
            i += 1;
        }
    }
    Ok((positional, auth_dir))
}

fn read_line_from_stdin() -> Result<Option<String>, String> {
    let stdin = std::io::stdin();
    let mut line = String::new();
    let n = stdin
        .lock()
        .read_line(&mut line)
        .map_err(|e| format!("reading stdin: {e}"))?;
    if n == 0 {
        return Ok(None); // EOF
    }
    Ok(Some(line))
}

fn guidance(kind: &str) -> &'static str {
    match kind {
        "capturing" => "Capturing…",
        "no-face" => "No face detected — look at the camera and hold still.",
        "multiple-faces" => "Multiple faces detected — make sure only you are in frame.",
        "too-dark" => "Too dark — face a light source and try again.",
        "too-bright" => "Too bright — move away from direct light and try again.",
        "duplicate-pose" => "Too similar — turn your head slightly and try again.",
        "matched" => "Face matched.",
        "not-matched" => "Face not matched — try again.",
        "stored" => "Capture stored.",
        "error" => "Capture failed — check the camera and try again.",
        _ => "Try again.",
    }
}

fn proxy() -> Result<zbus::blocking::Proxy<'static>, String> {
    let conn = zbus::blocking::Connection::system()
        .map_err(|e| format!("connecting to system bus: {e}"))?;
    zbus::blocking::Proxy::new(
        &conn,
        "org.zdr.Authenticator",
        "/org/zdr/Authenticator",
        "org.zdr.Authenticator",
    )
    .map_err(|e| format!("creating daemon proxy: {e}"))
}

fn cmd_enroll(args: &[String]) -> Result<(), String> {
    if effective_uid() != Some(0) {
        return Err(
            "enroll must run as root — run with sudo: sudo zdrctl enroll [user]".to_string(),
        );
    }
    let (positional, _auth_dir) = parse_auth_dir(args)?;
    let user = match positional.first() {
        Some(u) => u.clone(),
        None => match std::env::var("SUDO_USER") {
            Ok(u) if valid_user(&u) && u != "root" => u,
            _ => {
                return Err(
                    "no user given and $SUDO_USER is not set; usage: sudo zdrctl enroll <user>"
                        .to_string(),
                )
            }
        },
    };
    if !valid_user(&user) {
        return Err(format!("invalid user name {user:?}"));
    }
    let proxy = proxy()?;
    let enroll_id: String = proxy
        .call("BeginEnroll", &(user.as_str(),))
        .map_err(|e| format!("BeginEnroll({user}): {e}"))?;
    println!("Enrolling {user}: 5 captures needed. Follow the prompts; each good capture is kept.");
    let result = enroll_loop(&proxy, &enroll_id, &user);
    if result.is_err() {
        let _: Result<(), _> = proxy.call("CancelEnroll", &(enroll_id.as_str(),));
    }
    result
}

fn enroll_loop(
    proxy: &zbus::blocking::Proxy<'_>,
    enroll_id: &str,
    user: &str,
) -> Result<(), String> {
    let mut captured: i32 = 0;
    let mut needed: i32 = 5;
    while captured < needed {
        let pose = POSES[(captured as usize).min(POSES.len() - 1)];
        print!(
            "Capture {}/{}: {}. Press Enter to capture (Ctrl-D to abort)… ",
            captured + 1,
            needed,
            pose
        );
        std::io::stdout()
            .flush()
            .map_err(|e| format!("flushing stdout: {e}"))?;
        match read_line_from_stdin()? {
            Some(_) => {}
            None => return Err("enrollment aborted".to_string()),
        }
        let (state, got, need, kind): (String, i32, i32, String) = proxy
            .call("EnrollCapture", &(enroll_id,))
            .map_err(|e| format!("EnrollCapture: {e}"))?;
        captured = got;
        needed = need;
        println!("  {} ({}/{}, {})", guidance(&kind), captured, needed, state);
        if state == "ready" {
            break;
        }
    }
    let stored: i32 = proxy
        .call("FinishEnroll", &(enroll_id,))
        .map_err(|e| format!("FinishEnroll: {e}"))?;
    println!("Enrolled {stored} template(s) for {user}.");
    Ok(())
}

/// Count templates in one `templates.bin` payload (header: magic
/// "ZDRT", u16 version, u32 count, then count * 128 f32). Duplicated
/// in miniature here so zdrctl needs no daemon/engine code.
fn count_templates(bytes: &[u8]) -> Result<usize, String> {
    const HEADER: usize = 10;
    const DIM_BYTES: usize = 128 * 4;
    if bytes.len() < HEADER {
        return Err(format!("file too short ({} bytes)", bytes.len()));
    }
    if &bytes[0..4] != b"ZDRT" {
        return Err("bad magic (expected ZDRT)".to_string());
    }
    let version = u16::from_le_bytes([bytes[4], bytes[5]]);
    if version != 1 {
        return Err(format!("unsupported version {version}"));
    }
    let count = u32::from_le_bytes([bytes[6], bytes[7], bytes[8], bytes[9]]) as usize;
    if bytes.len() != HEADER + count * DIM_BYTES {
        return Err(format!(
            "size mismatch for {count} templates (wrong dimension or corrupt)"
        ));
    }
    Ok(count)
}

fn cmd_list(args: &[String]) -> Result<(), String> {
    let (_positional, auth_dir) = parse_auth_dir(args)?;
    let mut users: Vec<PathBuf> = match std::fs::read_dir(&auth_dir) {
        Ok(rd) => rd
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.is_dir())
            .collect(),
        Err(e) => return Err(format!("reading {}: {e}", auth_dir.display())),
    };
    users.sort();
    if users.is_empty() {
        println!("no users under {}", auth_dir.display());
        return Ok(());
    }
    for dir in users {
        let name = match dir.file_name() {
            Some(n) => n.to_string_lossy().into_owned(),
            None => dir.display().to_string(),
        };
        let bin = dir.join("templates.bin");
        match std::fs::read(&bin) {
            Ok(bytes) => match count_templates(&bytes) {
                Ok(n) => println!("{name}: {n} template(s)"),
                Err(e) => println!("{name}: corrupt templates.bin ({e})"),
            },
            Err(_) => println!("{name}: 0 template(s) (no templates.bin)"),
        }
    }
    Ok(())
}

fn cmd_remove(args: &[String]) -> Result<(), String> {
    let (positional, auth_dir) = parse_auth_dir(args)?;
    let user = positional
        .first()
        .ok_or_else(|| "usage: zdrctl remove <user>".to_string())?;
    if !valid_user(user) {
        return Err(format!("invalid user name {user:?}"));
    }
    let dir: &Path = &auth_dir.join(user);
    if !dir.is_dir() {
        return Err(format!(
            "no template directory for {user} at {}",
            dir.display()
        ));
    }
    print!("Remove all face templates for '{user}'? [y/N] ");
    std::io::stdout()
        .flush()
        .map_err(|e| format!("flushing stdout: {e}"))?;
    let answer = match read_line_from_stdin()? {
        Some(line) => line,
        None => String::new(),
    };
    let answer = answer.trim().to_ascii_lowercase();
    if answer != "y" && answer != "yes" {
        println!("Aborted.");
        return Ok(());
    }
    let mut removed = 0usize;
    let bin = dir.join("templates.bin");
    if bin.is_file() {
        std::fs::remove_file(&bin).map_err(|e| format!("removing {}: {e}", bin.display()))?;
        removed += 1;
    }
    let rd = std::fs::read_dir(dir).map_err(|e| format!("reading {}: {e}", dir.display()))?;
    for entry in rd.filter_map(|e| e.ok()) {
        let path = entry.path();
        let is_png_template = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => {
                let n = n.to_ascii_lowercase();
                n.starts_with("ir") && n.ends_with(".png")
            }
            None => false,
        };
        if is_png_template {
            std::fs::remove_file(&path).map_err(|e| format!("removing {}: {e}", path.display()))?;
            removed += 1;
        }
    }
    println!("Removed {removed} template file(s) for {user}.");
    Ok(())
}

fn cmd_test(args: &[String]) -> Result<(), String> {
    let (positional, _auth_dir) = parse_auth_dir(args)?;
    let user = positional
        .first()
        .ok_or_else(|| "usage: zdrctl test <user>".to_string())?;
    if !valid_user(user) {
        return Err(format!("invalid user name {user:?}"));
    }
    println!("To test authentication for {user}, use pamtester; live verify is a PAM operation.");
    println!("There is intentionally no daemon verify shortcut in zdrctl.");
    println!("Example (with a PAM service that loads pam_zdr, e.g. sudo):");
    println!("  pamtester -v sudo {user} authenticate");
    Ok(())
}
