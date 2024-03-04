use dlib_face_recognition::*;
use image;
use std::io;

pub struct Recognizer {
    ratio: f64,
    detector: FaceDetectorCnn,
    predictor: LandmarkPredictor,
    encoder: FaceEncoderNetwork,
    auth_images: Vec<FaceEncoding>,
}

impl Recognizer {
    pub fn new(
        ratio: f64,
        detector_db: &str,
        predictor_db: &str,
        encoder_db: &str,
    ) -> Result<Recognizer, String> {
        let detector = FaceDetectorCnn::open(detector_db)?;
        let predictor = LandmarkPredictor::open(predictor_db)?;
        let encoder = FaceEncoderNetwork::open(encoder_db)?;

        return Ok(Recognizer {
            ratio: ratio,
            detector: detector,
            predictor: predictor,
            encoder: encoder,
            auth_images: Vec::new(),
        });
    }

    pub fn load_auth_images(&mut self, path: &str) -> Result<Vec<FaceEncoding>, io::Error> {
        let mut encodings = Vec::new();
        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                continue;
            }
            let img = image::open(&path).unwrap().to_rgb8();
            let matrix = ImageMatrix::from_image(&img);
            let faces = self.detector.face_locations(&matrix);
            if faces.len() != 1 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Image must contain exactly one face",
                ));
            }
            let landmarks = self.predictor.face_landmarks(&matrix, &faces[0]);
            let descriptor = self.encoder.get_face_encodings(&matrix, &[landmarks], 0);
            encodings.push(descriptor[0].clone());
        }
        if encodings.len() == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "No valid images found",
            ));
        }
        self.auth_images = encodings.clone();
        Ok(encodings)
    }

    pub fn recognize(&self, img: &image::RgbImage) -> bool {
        let matrix = ImageMatrix::from_image(img);
        let faces = self.detector.face_locations(&matrix);
        if faces.len() != 1 {
            println!("Expected exactly 1 face, found {:?}", faces.len());
            return false;
        }
        let landmarks = self.predictor.face_landmarks(&matrix, &faces[0]);
        let descriptor = self.encoder.get_face_encodings(&matrix, &[landmarks], 0);

        for auth in &self.auth_images {
            let distance = auth.distance(&descriptor[0]);
            if distance < self.ratio {
                return true;
            }
        }
        false
    }
}
