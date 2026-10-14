//! Auth feedback kinds (Steps 10/11, frozen wire contract).
//!
//! Emitted over D-Bus as signal `AuthFeedback(request_id, kind, message)`.
//! `kind` is one of the `as_str` values below; `message` is a short human
//! sentence for display by agents / `zdrctl`.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeedbackKind {
    Capturing,
    NoFace,
    MultipleFaces,
    TooDark,
    TooBright,
    DuplicatePose,
    Matched,
    NotMatched,
    Stored,
    Error,
}

impl FeedbackKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            FeedbackKind::Capturing => "capturing",
            FeedbackKind::NoFace => "no-face",
            FeedbackKind::MultipleFaces => "multiple-faces",
            FeedbackKind::TooDark => "too-dark",
            FeedbackKind::TooBright => "too-bright",
            FeedbackKind::DuplicatePose => "duplicate-pose",
            FeedbackKind::Matched => "matched",
            FeedbackKind::NotMatched => "not-matched",
            FeedbackKind::Stored => "stored",
            FeedbackKind::Error => "error",
        }
    }

    pub fn message(&self) -> &'static str {
        match self {
            FeedbackKind::Capturing => "Capturing your face.",
            FeedbackKind::NoFace => "No face detected.",
            FeedbackKind::MultipleFaces => "Multiple faces detected.",
            FeedbackKind::TooDark => "Too dark; face the light.",
            FeedbackKind::TooBright => "Too bright; avoid direct light.",
            FeedbackKind::DuplicatePose => "Too similar; turn your head slightly.",
            FeedbackKind::Matched => "Face matched.",
            FeedbackKind::NotMatched => "Face not matched.",
            FeedbackKind::Stored => "Capture stored.",
            FeedbackKind::Error => "Verification failed.",
        }
    }

    /// Terminal feedback for a finished CaptureVerify, matching the
    /// existing `(matched, reason)` semantics exactly:
    /// `match`->matched, `nomatch`->not-matched, `noface-*`->no-face,
    /// everything else (camera/engine/not-approved/expired/unknown)
    /// fails closed as `error`.
    pub fn terminal_for_verify(matched: bool, reason: &str) -> FeedbackKind {
        if matched {
            return FeedbackKind::Matched;
        }
        match reason {
            "match" => FeedbackKind::Matched,
            "nomatch" => FeedbackKind::NotMatched,
            "noface-ir" | "noface-rgb" | "noface" => FeedbackKind::NoFace,
            "multiple-faces" => FeedbackKind::MultipleFaces,
            "too-dark" => FeedbackKind::TooDark,
            "too-bright" => FeedbackKind::TooBright,
            _ => FeedbackKind::Error,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_outcome_mapping() {
        assert_eq!(
            FeedbackKind::terminal_for_verify(true, "match"),
            FeedbackKind::Matched
        );
        assert_eq!(
            FeedbackKind::terminal_for_verify(false, "nomatch"),
            FeedbackKind::NotMatched
        );
        assert_eq!(
            FeedbackKind::terminal_for_verify(false, "noface-ir"),
            FeedbackKind::NoFace
        );
        assert_eq!(
            FeedbackKind::terminal_for_verify(false, "noface-rgb"),
            FeedbackKind::NoFace
        );
        for reason in ["camera", "engine", "not-approved", "expired", "bogus"] {
            assert_eq!(
                FeedbackKind::terminal_for_verify(false, reason),
                FeedbackKind::Error,
                "reason {reason}"
            );
        }
        // matched flag wins even if a stray reason slips through.
        assert_eq!(
            FeedbackKind::terminal_for_verify(true, "nomatch"),
            FeedbackKind::Matched
        );
    }

    #[test]
    fn kind_strings_are_frozen() {
        let kinds = [
            (FeedbackKind::Capturing, "capturing"),
            (FeedbackKind::NoFace, "no-face"),
            (FeedbackKind::MultipleFaces, "multiple-faces"),
            (FeedbackKind::TooDark, "too-dark"),
            (FeedbackKind::TooBright, "too-bright"),
            (FeedbackKind::DuplicatePose, "duplicate-pose"),
            (FeedbackKind::Matched, "matched"),
            (FeedbackKind::NotMatched, "not-matched"),
            (FeedbackKind::Stored, "stored"),
            (FeedbackKind::Error, "error"),
        ];
        for (kind, want) in kinds {
            assert_eq!(kind.as_str(), want);
            assert!(!kind.message().is_empty());
        }
    }
}
