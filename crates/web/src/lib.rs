mod admin;
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
