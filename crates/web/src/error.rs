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

#[derive(Template)]
#[template(path = "error.html")]
struct ErrorTemplate<'a> {
    status_code: u16,
    title: &'a str,
    message: &'a str,
    back_href: &'a str,
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
        let title = self.status.canonical_reason().unwrap_or("Error");
        match (ErrorTemplate {
            status_code: self.status.as_u16(),
            title,
            message: &self.message,
            back_href: "/",
        })
        .render()
        {
            Ok(body) => (self.status, Html(body)).into_response(),
            Err(error) => {
                error!("failed to render HTTP error page: {error}");
                (self.status, self.message).into_response()
            }
        }
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

pub(crate) async fn not_found() -> WebError {
    WebError {
        status: StatusCode::NOT_FOUND,
        message: "That page does not exist.".into(),
    }
}

pub(crate) async fn method_not_allowed() -> WebError {
    WebError {
        status: StatusCode::METHOD_NOT_ALLOWED,
        message: "That action is not available for this URL.".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use askama::{FastWritable, NO_VALUES, Values};
    use axum::{body::to_bytes, http::header};
    use pyregistry_domain::DomainError;
    use std::fmt;

    #[derive(Template)]
    #[template(source = "Hello {{ name }}", ext = "html")]
    struct GreetingTemplate<'a> {
        name: &'a str,
    }

    struct FailingTemplate;

    impl fmt::Display for FailingTemplate {
        fn fmt(&self, _formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            Err(fmt::Error)
        }
    }

    impl FastWritable for FailingTemplate {
        fn write_into<W: fmt::Write + ?Sized>(
            &self,
            _dest: &mut W,
            _values: &dyn Values,
        ) -> askama::Result<()> {
            Err(askama::Error::Fmt)
        }
    }

    impl Template for FailingTemplate {
        fn render_into_with_values<W: fmt::Write + ?Sized>(
            &self,
            _writer: &mut W,
            _values: &dyn Values,
        ) -> askama::Result<()> {
            Err(askama::Error::Fmt)
        }

        const SIZE_HINT: usize = 0;
    }

    #[test]
    fn maps_application_errors_to_http_status_codes() {
        let cases = [
            (
                ApplicationError::NotFound("missing".into()),
                StatusCode::NOT_FOUND,
            ),
            (
                ApplicationError::Unauthorized("nope".into()),
                StatusCode::UNAUTHORIZED,
            ),
            (
                ApplicationError::Conflict("already exists".into()),
                StatusCode::CONFLICT,
            ),
            (
                ApplicationError::Domain(DomainError::InvalidValue {
                    field: "tenant_slug",
                    message: "must be URL-safe".into(),
                }),
                StatusCode::BAD_REQUEST,
            ),
            (
                ApplicationError::Cancelled("stopped".into()),
                StatusCode::REQUEST_TIMEOUT,
            ),
            (
                ApplicationError::External("upstream".into()),
                StatusCode::BAD_GATEWAY,
            ),
        ];

        for (error, expected_status) in cases {
            let web_error = WebError::from(error);
            assert_eq!(web_error.status, expected_status);
            assert!(!web_error.message.is_empty());
        }
    }

    #[tokio::test]
    async fn into_response_preserves_status_and_body() {
        let response = bad_request("bad input").into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(
            response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .is_some_and(|value| value.starts_with("text/html"))
        );

        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        let body = String::from_utf8(body.to_vec()).expect("utf8 body");
        assert!(body.contains("<!doctype html>"));
        assert!(body.contains("400"));
        assert!(body.contains("Bad Request"));
        assert!(body.contains("bad input"));
    }

    #[tokio::test]
    async fn into_response_handles_server_errors() {
        let response = WebError {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: "template exploded".into(),
        }
        .into_response();

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        let body = String::from_utf8(body.to_vec()).expect("utf8 body");
        assert!(body.contains("500"));
        assert!(body.contains("Internal Server Error"));
        assert!(body.contains("template exploded"));
    }

    #[test]
    fn renders_askama_template_to_html() {
        let html = render_html(GreetingTemplate { name: "Pyregistry" }).expect("html");

        assert_eq!(html.0, "Hello Pyregistry");
    }

    #[test]
    fn maps_template_render_errors_to_internal_server_error() {
        let error = render_html(FailingTemplate).expect_err("render error");

        assert_eq!(error.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(!error.message.is_empty());
    }

    #[test]
    fn failing_template_reports_display_and_fast_write_errors() {
        let mut rendered = String::new();
        assert!(fmt::write(&mut rendered, format_args!("{}", FailingTemplate)).is_err());

        let mut rendered = String::new();
        assert!(FastWritable::write_into(&FailingTemplate, &mut rendered, NO_VALUES).is_err());
    }

    #[test]
    fn bad_request_builds_client_error() {
        let error = bad_request("invalid form");

        assert_eq!(error.status, StatusCode::BAD_REQUEST);
        assert_eq!(error.message, "invalid form");
    }
}
