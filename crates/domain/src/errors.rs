use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DomainError {
    #[error("invalid value for {field}: {message}")]
    InvalidValue {
        field: &'static str,
        message: String,
    },
    #[error("duplicate artifact filename `{0}` in release")]
    DuplicateArtifactFilename(String),
    #[error("mirrored projects cannot be purged")]
    MirroredProjectPurgeForbidden,
    #[error("trusted publisher claims do not match")]
    TrustedPublisherMismatch,
}
