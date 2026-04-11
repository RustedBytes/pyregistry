mod admin;
mod audit;
mod auth;
mod error;
mod models;
mod package_api;
mod rate_limit;
mod state;

pub use rate_limit::{RateLimitConfig, RateLimiter};
pub use state::{AppState, MirrorJobs};

use axum::{
    Router, middleware,
    routing::{get, post},
};

#[must_use]
pub fn router(state: AppState) -> Router {
    let rate_limit_layer =
        middleware::from_fn_with_state(state.clone(), rate_limit::enforce_api_rate_limit);

    Router::new()
        .route("/", get(admin::index))
        .route(
            "/admin/login",
            get(admin::login_form).post(admin::login_submit),
        )
        .route("/admin/dashboard", get(admin::dashboard))
        .route("/admin/logout", post(admin::logout))
        .route("/admin/tenants", post(admin::create_tenant))
        .route("/admin/search", get(admin::search))
        .route("/admin/t/{tenant}/tokens", post(admin::issue_token))
        .route(
            "/admin/t/{tenant}/mirror-cache",
            post(admin::cache_mirror_project),
        )
        .route(
            "/admin/t/{tenant}/publishers",
            post(admin::register_publisher),
        )
        .route("/admin/t/{tenant}/packages", get(admin::package_list))
        .route(
            "/admin/t/{tenant}/packages/{project}",
            get(admin::package_detail),
        )
        .route(
            "/admin/t/{tenant}/packages/{project}/releases/{version}/yank",
            post(admin::yank_release),
        )
        .route(
            "/admin/t/{tenant}/packages/{project}/releases/{version}/unyank",
            post(admin::unyank_release),
        )
        .route(
            "/admin/t/{tenant}/packages/{project}/releases/{version}/purge",
            post(admin::purge_release),
        )
        .route(
            "/admin/t/{tenant}/packages/{project}/releases/{version}/artifacts/{filename}/yank",
            post(admin::yank_artifact),
        )
        .route(
            "/admin/t/{tenant}/packages/{project}/releases/{version}/artifacts/{filename}/unyank",
            post(admin::unyank_artifact),
        )
        .route(
            "/admin/t/{tenant}/packages/{project}/releases/{version}/artifacts/{filename}/purge",
            post(admin::purge_artifact),
        )
        .route(
            "/admin/t/{tenant}/packages/{project}/releases/{version}/artifacts/{filename}/download",
            get(admin::download_artifact),
        )
        .route(
            "/admin/t/{tenant}/packages/{project}/releases/{version}/artifacts/{filename}/scan",
            post(admin::scan_artifact),
        )
        .route("/t/{tenant}/simple/", get(package_api::simple_index))
        .route(
            "/t/{tenant}/simple/{project}/",
            get(package_api::simple_project),
        )
        .route("/t/{tenant}/legacy/", post(package_api::legacy_upload))
        .route(
            "/t/{tenant}/files/{project}/{version}/{filename}",
            get(package_api::download_artifact),
        )
        .route(
            "/t/{tenant}/provenance/{project}/{version}/{filename}",
            get(package_api::get_provenance),
        )
        .route("/_/oidc/audience", get(package_api::oidc_audience))
        .route(
            "/_/oidc/mint-token",
            post(package_api::mint_oidc_publish_token),
        )
        .layer(rate_limit_layer)
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode, header},
    };
    use base64::Engine;
    use http_body_util::BodyExt;
    use pyregistry_application::IssueApiTokenCommand;
    use pyregistry_domain::TokenScope;
    use pyregistry_infrastructure::{
        DatabaseStoreKind, Settings, build_application, seed_application,
    };
    use std::{collections::HashMap, sync::Arc};
    use tokio::sync::RwLock;
    use tower::ServiceExt;
    use uuid::Uuid;

    async fn state() -> AppState {
        let mut settings = Settings::new_local_template();
        settings.database_store = DatabaseStoreKind::InMemory;
        settings.blob_root =
            std::env::temp_dir().join(format!("pyregistry-web-{}", Uuid::new_v4()));
        let app = build_application(&settings).await.expect("application");
        seed_application(&app, &settings).await.expect("seed");

        AppState {
            app,
            sessions: Arc::new(RwLock::new(HashMap::new())),
            mirror_jobs: Arc::new(RwLock::new(HashMap::new())),
            rate_limiter: RateLimiter::disabled(),
        }
    }

    async fn body_text(response: axum::response::Response) -> String {
        let bytes = response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        String::from_utf8(bytes.to_vec()).expect("utf8 body")
    }

    fn basic_token(secret: &str) -> String {
        let encoded =
            base64::engine::general_purpose::STANDARD.encode(format!("__token__:{secret}"));
        format!("Basic {encoded}")
    }

    #[tokio::test]
    async fn router_serves_public_index_and_oidc_audience() {
        let app = router(state().await);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        assert!(body_text(response).await.contains("Pyregistry"));

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/_/oidc/audience")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        assert!(body_text(response).await.contains("pyregistry"));
    }

    #[tokio::test]
    async fn package_api_requires_auth_and_accepts_read_tokens() {
        let state = state().await;
        let issued = state
            .app
            .issue_api_token(IssueApiTokenCommand {
                tenant_slug: "acme".into(),
                label: "test-read".into(),
                scopes: vec![TokenScope::Read],
                ttl_hours: None,
            })
            .await
            .expect("token");
        let app = router(state);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/t/acme/simple/")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/t/acme/simple/")
                    .header(header::AUTHORIZATION, basic_token(&issued.secret))
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        assert!(body_text(response).await.contains("Simple index"));
    }

    #[tokio::test]
    async fn package_api_uploads_lists_and_downloads_artifacts() {
        let state = state().await;
        let issued = state
            .app
            .issue_api_token(IssueApiTokenCommand {
                tenant_slug: "acme".into(),
                label: "test-publish".into(),
                scopes: vec![TokenScope::Read, TokenScope::Publish],
                ttl_hours: None,
            })
            .await
            .expect("token");
        let auth = basic_token(&issued.secret);
        let app = router(state);
        let boundary = "PYREGISTRY_TEST_BOUNDARY";
        let body = concat!(
            "--PYREGISTRY_TEST_BOUNDARY\r\n",
            "Content-Disposition: form-data; name=\"name\"\r\n\r\n",
            "Demo_Pkg\r\n",
            "--PYREGISTRY_TEST_BOUNDARY\r\n",
            "Content-Disposition: form-data; name=\"version\"\r\n\r\n",
            "1.0.0\r\n",
            "--PYREGISTRY_TEST_BOUNDARY\r\n",
            "Content-Disposition: form-data; name=\"summary\"\r\n\r\n",
            "A demo package\r\n",
            "--PYREGISTRY_TEST_BOUNDARY\r\n",
            "Content-Disposition: form-data; name=\"description\"\r\n\r\n",
            "Long description\r\n",
            "--PYREGISTRY_TEST_BOUNDARY\r\n",
            "Content-Disposition: form-data; name=\"content\"; filename=\"demo_pkg-1.0.0-py3-none-any.whl\"\r\n",
            "Content-Type: application/octet-stream\r\n\r\n",
            "fake wheel bytes\r\n",
            "--PYREGISTRY_TEST_BOUNDARY--\r\n"
        );

        let upload = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/t/acme/legacy/")
                    .header(header::AUTHORIZATION, auth.clone())
                    .header(
                        header::CONTENT_TYPE,
                        format!("multipart/form-data; boundary={boundary}"),
                    )
                    .body(Body::from(body))
                    .expect("request"),
            )
            .await
            .expect("upload response");
        assert_eq!(upload.status(), StatusCode::OK);

        let project = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/t/acme/simple/demo-pkg/")
                    .header(header::AUTHORIZATION, auth.clone())
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("project response");
        assert_eq!(project.status(), StatusCode::OK);
        assert!(
            body_text(project)
                .await
                .contains("demo_pkg-1.0.0-py3-none-any.whl")
        );

        let download = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/t/acme/files/demo-pkg/1.0.0/demo_pkg-1.0.0-py3-none-any.whl")
                    .header(header::AUTHORIZATION, auth.clone())
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("download response");
        assert_eq!(download.status(), StatusCode::OK);
        assert_eq!(body_text(download).await, "fake wheel bytes");

        let provenance = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/t/acme/provenance/demo-pkg/1.0.0/demo_pkg-1.0.0-py3-none-any.whl")
                    .header(header::AUTHORIZATION, auth)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("provenance response");
        assert_eq!(provenance.status(), StatusCode::NOT_FOUND);

        let mint = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/_/oidc/mint-token")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"tenant_slug":"acme","project_name":"demo-pkg","oidc_token":"bad"}"#,
                    ))
                    .expect("request"),
            )
            .await
            .expect("mint response");
        assert_eq!(mint.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn admin_login_sets_session_cookie_and_dashboard_uses_it() {
        let app = router(state().await);

        let login_form = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/admin/login")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(login_form.status(), StatusCode::OK);

        let login = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/admin/login")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(
                        "email=admin%40pyregistry.local&password=change-me-now",
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(login.status(), StatusCode::SEE_OTHER);
        let cookie = login
            .headers()
            .get(header::SET_COOKIE)
            .expect("set-cookie")
            .to_str()
            .expect("cookie")
            .split(';')
            .next()
            .expect("cookie pair")
            .to_string();

        let dashboard = app
            .oneshot(
                Request::builder()
                    .uri("/admin/dashboard")
                    .header(header::COOKIE, cookie)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(dashboard.status(), StatusCode::OK);
        assert!(body_text(dashboard).await.contains("Dashboard"));
    }
}
