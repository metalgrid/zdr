use std::io::{self};

use image::RgbImage;
use v4l::buffer::Type::VideoCapture;
use v4l::framesize::{Discrete, FrameSizeEnum};
use v4l::io::traits::CaptureStream;
use v4l::prelude::*;
use v4l::video::Capture;
use v4l::FourCC;
pub struct Snap {
    dev: Device,
}

impl Snap {
    pub fn new(dev: &str) -> Result<Snap, io::Error> {
        let dev = Device::with_path(dev)?;
        let mut format = dev.format()?;
        let mut size: u32 = 0;
        for fmt in dev.enum_formats()? {
            for fs in dev.enum_framesizes(fmt.fourcc)? {
                // We don't support anything other than MJPG for now
                if fs.fourcc != FourCC::new(b"MJPG") {
                    continue;
                }
                match fs.size {
                    FrameSizeEnum::Discrete(Discrete { width, height }) => {
                        let s = width * height;
                        if s > size {
                            size = s;
                            format.width = width;
                            format.height = height;
                            format.fourcc = fs.fourcc;
                        }
                    }
                    _ => {}
                }
            }
        }
        dev.set_format(&format)?;
        Ok(Snap { dev })
    }

    pub fn take_snap(&self) -> Result<RgbImage, io::Error> {
        let mut stream = MmapStream::with_buffers(&self.dev, VideoCapture, 1)?;
        let (buf, _) = stream.next()?;
        match image::load_from_memory(buf) {
            Ok(img) => Ok(img.to_rgb8()),
            Err(e) => Err(io::Error::new(io::ErrorKind::InvalidData, e)),
        }
    }
}
