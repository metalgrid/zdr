mod args;
mod recognize;
mod snap;

use std::sync::Mutex;

use args::Args;
use clap::Parser;
use event_listener::Listener;
use recognize::Recognizer;
use snap::Snap;
use zbus::blocking::connection::Builder;

fn main() -> Result<(), zbus::Error> {
    let args = Args::parse();
    let mut rec = Recognizer::new(
        args.r,
        args.ddb.as_str(),
        args.pdb.as_str(),
        args.rdb.as_str(),
    )
    .unwrap();

    rec.load_auth_images(args.auth_dir.as_str()).unwrap();

    let snap = Snap::new(args.camera.as_str()).unwrap();

    let svc = ZdrService {
        event: event_listener::Event::new(),
        rec: Mutex::new(rec),
        snap: snap,
    };
    let listener = svc.event.listen();

    let _bus = Builder::system()?
        .name("org.zdr.Authenticator")?
        .serve_at("/org/zdr/Authenticator", svc)?
        .build()?;

    listener.wait();
    Ok(())
}

struct ZdrService {
    event: event_listener::Event,
    rec: Mutex<Recognizer>, // This is awful, but I've been banging my head against the wall for hours
    snap: Snap,
}

#[zbus::interface(name = "org.zdr.Authenticator")]
impl ZdrService {
    fn verify(&self, user: &str) -> Result<bool, zbus::fdo::Error> {
        let img = self.snap.take_snap().unwrap();
        let rec = self.rec.lock().unwrap();
        Ok(rec.recognize(&img))
    }
}
