use pyregistry_domain::DomainError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ApplicationError {
    #[error("{0}")]
    Domain(#[from] DomainError),
    #[error("resource not found: {0}")]
    NotFound(String),
    #[error("conflict: {0}")]
    Conflict(String),
    #[error("unauthorized: {0}")]
    Unauthorized(String),
    #[error("external dependency failure: {0}")]
    External(String),
}
