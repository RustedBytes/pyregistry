use askama::Template;
use axum::{
    extract::multipart::MultipartError,
    http::StatusCode,
    response::{Html, IntoResponse, Response},
};
use log::{error, warn};
use pyregistry_application::ApplicationError;

#[derive(Debug)]
pub struct WebError {
    pub(crate) status: StatusCode,
    pub(crate) message: String,
}

impl From<ApplicationError> for WebError {
    fn from(value: ApplicationError) -> Self {
        let status = match value {
            ApplicationError::NotFound(_) => StatusCode::NOT_FOUND,
            ApplicationError::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            ApplicationError::Conflict(_) => StatusCode::CONFLICT,
            ApplicationError::Domain(_) => StatusCode::BAD_REQUEST,
            ApplicationError::Cancelled(_) => StatusCode::REQUEST_TIMEOUT,
            ApplicationError::External(_) => StatusCode::BAD_GATEWAY,
        };
        Self {
            status,
            message: value.to_string(),
        }
    }
}

impl IntoResponse for WebError {
    fn into_response(self) -> Response {
        if self.status.is_server_error() {
            error!("returning HTTP {}: {}", self.status, self.message);
        } else {
            warn!("returning HTTP {}: {}", self.status, self.message);
        }
        (self.status, self.message).into_response()
    }
}

pub(crate) fn render_html<T: Template>(template: T) -> Result<Html<String>, WebError> {
    template.render().map(Html).map_err(|error| WebError {
        status: StatusCode::INTERNAL_SERVER_ERROR,
        message: error.to_string(),
    })
}

pub(crate) fn to_bad_request(error: MultipartError) -> WebError {
    bad_request(&error.to_string())
}

pub(crate) fn bad_request(message: &str) -> WebError {
    WebError {
        status: StatusCode::BAD_REQUEST,
        message: message.into(),
    }
}
