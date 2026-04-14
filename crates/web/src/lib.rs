mod admin;
mod audit;
mod auth;
mod error;
mod models;
mod network_source;
mod package_api;
mod rate_limit;
mod state;

pub use network_source::{NetworkSourceConfig, NetworkSourcePolicy};
pub use rate_limit::{RateLimitConfig, RateLimiter};
pub use state::{AppState, MirrorJobs};

use axum::{
    Router,
    extract::DefaultBodyLimit,
    middleware,
    routing::{get, post},
};

const MAX_REQUEST_BODY_BYTES: usize = 100 * 1024 * 1024;

pub fn router(state: AppState) -> Router {
    let rate_limit_layer =
        middleware::from_fn_with_state(state.clone(), rate_limit::enforce_api_rate_limit);
    let network_source_layer = middleware::from_fn_with_state(
        state.clone(),
        network_source::enforce_network_source_access,
    );
    let admin_csrf_layer = middleware::from_fn(admin::enforce_admin_origin);

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
        .route("/admin/t/{tenant}/tokens/revoke", post(admin::revoke_token))
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
            "/admin/t/{tenant}/packages/{project}/remove",
            post(admin::remove_package),
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
        .method_not_allowed_fallback(error::method_not_allowed)
        .fallback(error::not_found)
        .layer(DefaultBodyLimit::max(MAX_REQUEST_BODY_BYTES))
        .layer(admin_csrf_layer)
        .layer(rate_limit_layer)
        .layer(network_source_layer)
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
    use chrono::{TimeZone, Utc};
    use http_body_util::BodyExt;
    use pyregistry_application::{
        AdminSession, ApplicationError, AttestationSigner, Clock, CreateTenantCommand,
        DependencyVulnerabilityQuery, DependencyVulnerabilityReport, DistributionFileInspector,
        DistributionInspection, DistributionKind, FileTypeInspection, IdGenerator,
        IssueApiTokenCommand, MirrorClient, MirroredProjectSnapshot, NoopPackagePublishNotifier,
        NoopVulnerabilityNotifier, NoopWheelAuditNotifier, ObjectStorage, OidcVerifier,
        PackageVulnerabilityQuery, PackageVulnerabilityReport, PasswordHasher, PyregistryApp,
        RegisterTrustedPublisherCommand, TokenHasher, UploadArtifactCommand, VulnerabilityScanner,
        WheelArchiveEntry, WheelArchiveReader, WheelArchiveSnapshot, WheelSourceSecurityScanResult,
        WheelSourceSecurityScanner, WheelVirusScanResult, WheelVirusScanner,
    };
    use pyregistry_domain::{
        Artifact, ProjectName, PublishIdentity, ReleaseVersion, TokenScope,
        TrustedPublisherProvider,
    };
    use std::{collections::HashMap, sync::Arc};
    use tokio::sync::RwLock;
    use tower::ServiceExt;
    use uuid::Uuid;

    struct MemoryObjectStorage {
        objects: RwLock<HashMap<String, Vec<u8>>>,
    }

    #[async_trait::async_trait]
    impl ObjectStorage for MemoryObjectStorage {
        async fn put(&self, key: &str, bytes: Vec<u8>) -> Result<(), ApplicationError> {
            self.objects.write().await.insert(key.to_string(), bytes);
            Ok(())
        }

        async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, ApplicationError> {
            Ok(self.objects.read().await.get(key).cloned())
        }

        async fn delete(&self, key: &str) -> Result<(), ApplicationError> {
            self.objects.write().await.remove(key);
            Ok(())
        }
    }

    struct EmptyMirrorClient;

    #[async_trait::async_trait]
    impl MirrorClient for EmptyMirrorClient {
        async fn fetch_project(
            &self,
            _project_name: &str,
        ) -> Result<Option<MirroredProjectSnapshot>, ApplicationError> {
            Ok(None)
        }

        async fn fetch_artifact_bytes(
            &self,
            _download_url: &str,
        ) -> Result<Vec<u8>, ApplicationError> {
            Err(ApplicationError::NotFound("artifact".into()))
        }
    }

    struct RejectingOidcVerifier;

    #[async_trait::async_trait]
    impl OidcVerifier for RejectingOidcVerifier {
        async fn verify(
            &self,
            _token: &str,
            _audience: &str,
        ) -> Result<PublishIdentity, ApplicationError> {
            Err(ApplicationError::Unauthorized("invalid OIDC token".into()))
        }
    }

    struct AcceptingOidcVerifier;

    #[async_trait::async_trait]
    impl OidcVerifier for AcceptingOidcVerifier {
        async fn verify(
            &self,
            _token: &str,
            audience: &str,
        ) -> Result<PublishIdentity, ApplicationError> {
            Ok(PublishIdentity {
                issuer: "https://token.actions.githubusercontent.com".into(),
                subject: "repo:acme/demo-pkg:ref:refs/heads/main".into(),
                audience: audience.to_string(),
                provider: TrustedPublisherProvider::GitHubActions,
                claims: HashMap::from([
                    ("repository".into(), "acme/demo-pkg".into()),
                    ("ref".into(), "refs/heads/main".into()),
                ])
                .into_iter()
                .collect(),
            })
        }
    }

    struct TestAttestationSigner;

    #[async_trait::async_trait]
    impl AttestationSigner for TestAttestationSigner {
        async fn build_attestation(
            &self,
            project_name: &ProjectName,
            version: &ReleaseVersion,
            artifact: &Artifact,
            identity: &PublishIdentity,
        ) -> Result<String, ApplicationError> {
            Ok(serde_json::json!({
                "project": project_name.normalized(),
                "version": version.as_str(),
                "filename": artifact.filename,
                "issuer": identity.issuer
            })
            .to_string())
        }
    }

    struct PlainPasswordHasher;

    impl PasswordHasher for PlainPasswordHasher {
        fn hash(&self, password: &str) -> Result<String, ApplicationError> {
            Ok(password.to_string())
        }

        fn verify(&self, password: &str, hash: &str) -> Result<bool, ApplicationError> {
            Ok(password == hash)
        }
    }

    struct PlainTokenHasher;

    impl TokenHasher for PlainTokenHasher {
        fn hash(&self, secret: &str) -> Result<String, ApplicationError> {
            Ok(secret.to_string())
        }
    }

    struct CleanVulnerabilityScanner;

    #[async_trait::async_trait]
    impl VulnerabilityScanner for CleanVulnerabilityScanner {
        async fn scan_package_versions(
            &self,
            packages: &[PackageVulnerabilityQuery],
        ) -> Result<Vec<PackageVulnerabilityReport>, ApplicationError> {
            Ok(packages
                .iter()
                .map(PackageVulnerabilityReport::clean)
                .collect())
        }

        async fn scan_dependency_versions(
            &self,
            dependencies: &[DependencyVulnerabilityQuery],
        ) -> Result<Vec<DependencyVulnerabilityReport>, ApplicationError> {
            Ok(dependencies
                .iter()
                .map(DependencyVulnerabilityReport::clean)
                .collect())
        }
    }

    struct StaticWheelArchiveReader;

    impl WheelArchiveReader for StaticWheelArchiveReader {
        fn read_wheel(
            &self,
            path: &std::path::Path,
        ) -> Result<WheelArchiveSnapshot, ApplicationError> {
            Ok(WheelArchiveSnapshot {
                wheel_filename: path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or("demo.whl")
                    .to_string(),
                entries: vec![WheelArchiveEntry {
                    path: "demo/__init__.py".into(),
                    contents: b"print('ok')".to_vec(),
                }],
            })
        }

        fn read_wheel_bytes(
            &self,
            wheel_filename: &str,
            _bytes: &[u8],
        ) -> Result<WheelArchiveSnapshot, ApplicationError> {
            Ok(WheelArchiveSnapshot {
                wheel_filename: wheel_filename.to_string(),
                entries: vec![WheelArchiveEntry {
                    path: "demo/__init__.py".into(),
                    contents: b"print('ok')".to_vec(),
                }],
            })
        }
    }

    struct PermissiveDistributionInspector;

    impl DistributionFileInspector for PermissiveDistributionInspector {
        fn inspect_distribution(
            &self,
            _path: &std::path::Path,
        ) -> Result<DistributionInspection, ApplicationError> {
            Err(ApplicationError::External(
                "path distribution inspection is unused in web tests".into(),
            ))
        }

        fn inspect_distribution_bytes(
            &self,
            filename: &str,
            bytes: &[u8],
        ) -> Result<DistributionInspection, ApplicationError> {
            Ok(DistributionInspection {
                kind: if filename.ends_with(".whl") {
                    DistributionKind::Wheel
                } else if filename.ends_with(".zip") {
                    DistributionKind::SourceZip
                } else {
                    DistributionKind::SourceTarGz
                },
                size_bytes: bytes.len() as u64,
                sha256: "a".repeat(64),
                archive_entry_count: 1,
                file_type: FileTypeInspection {
                    detector: "test".into(),
                    label: "zip".into(),
                    mime_type: "application/zip".into(),
                    group: "archive".into(),
                    description: "Zip archive".into(),
                    score: 1.0,
                    actual_extension: Some("zip".into()),
                    expected_extensions: vec!["zip".into()],
                    matches_extension: true,
                },
            })
        }
    }

    struct NoopVirusScanner;

    impl WheelVirusScanner for NoopVirusScanner {
        fn scan_archive(
            &self,
            archive: &WheelArchiveSnapshot,
        ) -> Result<WheelVirusScanResult, ApplicationError> {
            Ok(WheelVirusScanResult {
                scanned_file_count: archive.entries.len(),
                signature_rule_count: 0,
                skipped_rule_count: 0,
                findings: Vec::new(),
            })
        }
    }

    struct NoopSourceSecurityScanner;

    impl WheelSourceSecurityScanner for NoopSourceSecurityScanner {
        fn scan_archive(
            &self,
            archive: &WheelArchiveSnapshot,
        ) -> Result<WheelSourceSecurityScanResult, ApplicationError> {
            Ok(WheelSourceSecurityScanResult {
                scanned_file_count: archive.entries.len(),
                findings: Vec::new(),
            })
        }
    }

    struct FixedClock;

    impl Clock for FixedClock {
        fn now(&self) -> chrono::DateTime<Utc> {
            Utc.with_ymd_and_hms(2026, 4, 11, 12, 0, 0)
                .single()
                .expect("timestamp")
        }
    }

    struct RandomIds;

    impl IdGenerator for RandomIds {
        fn next(&self) -> Uuid {
            Uuid::new_v4()
        }
    }

    async fn state() -> AppState {
        state_with_oidc(Arc::new(RejectingOidcVerifier)).await
    }

    async fn state_with_oidc(oidc_verifier: Arc<dyn OidcVerifier>) -> AppState {
        let app = Arc::new(PyregistryApp::new(
            Arc::new(pyregistry_infrastructure::InMemoryRegistryStore::default()),
            Arc::new(MemoryObjectStorage {
                objects: RwLock::new(HashMap::new()),
            }),
            Arc::new(EmptyMirrorClient),
            oidc_verifier,
            Arc::new(TestAttestationSigner),
            Arc::new(PlainPasswordHasher),
            Arc::new(PlainTokenHasher),
            Arc::new(CleanVulnerabilityScanner),
            Arc::new(NoopVulnerabilityNotifier),
            Arc::new(NoopPackagePublishNotifier),
            Arc::new(NoopWheelAuditNotifier),
            Arc::new(StaticWheelArchiveReader),
            Arc::new(PermissiveDistributionInspector),
            Arc::new(NoopVirusScanner),
            Arc::new(NoopSourceSecurityScanner),
            Arc::new(FixedClock),
            Arc::new(RandomIds),
            4,
        ));
        app.bootstrap_superadmin("admin@pyregistry.local", "change-me-now")
            .await
            .expect("superadmin");
        app.create_tenant(CreateTenantCommand {
            slug: "acme".into(),
            display_name: "Acme Corp".into(),
            mirroring_enabled: true,
            admin_email: "tenant-admin@acme.local".into(),
            admin_password: "change-me-now".into(),
        })
        .await
        .expect("tenant");

        AppState {
            app,
            sessions: Arc::new(RwLock::new(HashMap::new())),
            mirror_jobs: Arc::new(RwLock::new(HashMap::new())),
            rate_limiter: RateLimiter::disabled(),
            network_source: NetworkSourcePolicy::allow_all(),
            show_index_stats: true,
            secure_admin_cookies: false,
            external_base_url: None,
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

    async fn login_cookie(app: Router) -> String {
        let login = app
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
        login
            .headers()
            .get(header::SET_COOKIE)
            .expect("set-cookie")
            .to_str()
            .expect("cookie")
            .split(';')
            .next()
            .expect("cookie pair")
            .to_string()
    }

    async fn issue_token(state: &AppState, scopes: Vec<TokenScope>) -> String {
        state
            .app
            .issue_api_token(IssueApiTokenCommand {
                tenant_slug: "acme".into(),
                label: "test-token".into(),
                scopes,
                ttl_hours: None,
            })
            .await
            .expect("token")
            .secret
    }

    fn with_network_source(mut state: AppState, config: NetworkSourceConfig) -> AppState {
        state.network_source = NetworkSourcePolicy::new(config);
        state
    }

    fn with_rate_limit(mut state: AppState, config: RateLimitConfig) -> AppState {
        state.rate_limiter = RateLimiter::new(config);
        state
    }

    fn without_index_stats(mut state: AppState) -> AppState {
        state.show_index_stats = false;
        state
    }

    async fn upload_demo_package(app: Router, auth: &str) {
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
            "fake wheel bytes",
            "\r\n--PYREGISTRY_TEST_BOUNDARY--\r\n"
        );

        let upload = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/t/acme/legacy/")
                    .header(header::AUTHORIZATION, auth)
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
    async fn router_can_hide_public_index_stats() {
        let app = router(without_index_stats(state().await));

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK);
        let body = body_text(response).await;
        assert!(body.contains("Pyregistry"));
        assert!(!body.contains("Registry snapshot"));
        assert!(!body.contains("Registry metrics"));
    }

    #[tokio::test]
    async fn router_rejects_web_ui_requests_from_disallowed_network_sources() {
        let state = with_network_source(
            state().await,
            NetworkSourceConfig {
                web_ui_allowed_cidrs: vec!["10.0.0.0/8".into()],
                api_allowed_cidrs: Vec::new(),
                trust_proxy_headers: true,
            },
        );
        let app = router(state);

        let denied = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/admin/login")
                    .header("x-forwarded-for", "192.0.2.10")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("denied response");
        assert_eq!(denied.status(), StatusCode::FORBIDDEN);

        let allowed = app
            .oneshot(
                Request::builder()
                    .uri("/admin/login")
                    .header("x-forwarded-for", "10.1.2.3")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("allowed response");
        assert_eq!(allowed.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn router_rejects_api_requests_from_disallowed_network_sources() {
        let state = state().await;
        let token = basic_token(&issue_token(&state, vec![TokenScope::Read]).await);
        let app = router(with_network_source(
            state,
            NetworkSourceConfig {
                web_ui_allowed_cidrs: Vec::new(),
                api_allowed_cidrs: vec!["198.51.100.0/24".into()],
                trust_proxy_headers: true,
            },
        ));

        let denied = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/t/acme/simple/")
                    .header(header::AUTHORIZATION, token.clone())
                    .header("x-forwarded-for", "203.0.113.10")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("denied response");
        assert_eq!(denied.status(), StatusCode::FORBIDDEN);

        let allowed = app
            .oneshot(
                Request::builder()
                    .uri("/t/acme/simple/")
                    .header(header::AUTHORIZATION, token)
                    .header("x-forwarded-for", "198.51.100.10")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("allowed response");
        assert_eq!(allowed.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn router_renders_html_error_pages_for_missing_routes_and_methods() {
        let app = router(state().await);

        let missing = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/missing")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("missing response");
        assert_eq!(missing.status(), StatusCode::NOT_FOUND);
        assert!(
            missing
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .is_some_and(|value| value.starts_with("text/html"))
        );
        let missing_body = body_text(missing).await;
        assert!(missing_body.contains("<!doctype html>"));
        assert!(missing_body.contains("404"));
        assert!(missing_body.contains("Not Found"));

        let wrong_method = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("wrong method response");
        assert_eq!(wrong_method.status(), StatusCode::METHOD_NOT_ALLOWED);
        let wrong_method_body = body_text(wrong_method).await;
        assert!(wrong_method_body.contains("<!doctype html>"));
        assert!(wrong_method_body.contains("405"));
        assert!(wrong_method_body.contains("Method Not Allowed"));
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
        let auth =
            basic_token(&issue_token(&state, vec![TokenScope::Read, TokenScope::Publish]).await);
        let app = router(state);
        upload_demo_package(app.clone(), &auth).await;

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
    async fn package_api_lists_projects_serves_provenance_and_mints_oidc_tokens() {
        let state = state_with_oidc(Arc::new(AcceptingOidcVerifier)).await;
        state
            .app
            .register_trusted_publisher(RegisterTrustedPublisherCommand {
                tenant_slug: "acme".into(),
                project_name: "Demo_Pkg".into(),
                provider: TrustedPublisherProvider::GitHubActions,
                issuer: "https://token.actions.githubusercontent.com".into(),
                audience: "pyregistry".into(),
                claim_rules: HashMap::from([
                    ("repository".into(), "acme/demo-pkg".into()),
                    ("ref".into(), "refs/heads/main".into()),
                ])
                .into_iter()
                .collect(),
            })
            .await
            .expect("trusted publisher");
        let read_publish_auth =
            basic_token(&issue_token(&state, vec![TokenScope::Read, TokenScope::Publish]).await);
        let oidc_grant = state
            .app
            .mint_oidc_publish_token(pyregistry_application::MintOidcPublishTokenCommand {
                tenant_slug: "acme".into(),
                project_name: "Demo_Pkg".into(),
                oidc_token: "good.jwt".into(),
            })
            .await
            .expect("OIDC grant");
        let trusted_access = state
            .app
            .authenticate_tenant_token("acme", &oidc_grant.token, TokenScope::Publish)
            .await
            .expect("trusted access");
        state
            .app
            .upload_artifact(
                &trusted_access,
                UploadArtifactCommand {
                    tenant_slug: "acme".into(),
                    project_name: "Demo_Pkg".into(),
                    version: "2.0.0".into(),
                    filename: "demo_pkg-2.0.0-py3-none-any.whl".into(),
                    summary: "A demo package".into(),
                    description: "Trusted publish".into(),
                    content: b"trusted wheel bytes".to_vec(),
                },
            )
            .await
            .expect("trusted upload");
        let app = router(state);
        upload_demo_package(app.clone(), &read_publish_auth).await;

        let index = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/t/acme/simple/")
                    .header(header::AUTHORIZATION, read_publish_auth.clone())
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("index response");
        assert_eq!(index.status(), StatusCode::OK);
        assert!(body_text(index).await.contains("Demo_Pkg"));

        let provenance = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/t/acme/provenance/demo-pkg/2.0.0/demo_pkg-2.0.0-py3-none-any.whl")
                    .header(header::AUTHORIZATION, read_publish_auth)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("provenance response");
        assert_eq!(provenance.status(), StatusCode::OK);
        assert!(body_text(provenance).await.contains("token.actions"));

        let mint = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/_/oidc/mint-token")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"tenant_slug":"acme","project_name":"Demo_Pkg","oidc_token":"good.jwt"}"#,
                    ))
                    .expect("request"),
            )
            .await
            .expect("mint response");
        assert_eq!(mint.status(), StatusCode::OK);
        assert!(body_text(mint).await.contains("oidc_"));
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
            .expect("login response");
        assert_eq!(login.status(), StatusCode::SEE_OTHER);
        let set_cookie = login
            .headers()
            .get(header::SET_COOKIE)
            .expect("set-cookie")
            .to_str()
            .expect("cookie");
        assert!(set_cookie.contains("HttpOnly"));
        assert!(set_cookie.contains("SameSite=Strict"));
        assert!(set_cookie.contains("Max-Age="));

        let cookie = login_cookie(app.clone()).await;

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

    #[tokio::test]
    async fn admin_login_is_rate_limited() {
        let app = router(with_rate_limit(
            state().await,
            RateLimitConfig {
                enabled: true,
                requests_per_minute: 1,
                burst: 1,
                max_tracked_clients: 8,
                trust_proxy_headers: false,
            },
        ));

        let first = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/admin/login")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from("email=admin%40pyregistry.local&password=wrong"))
                    .expect("request"),
            )
            .await
            .expect("first login response");
        assert_eq!(first.status(), StatusCode::OK);

        let second = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/admin/login")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from("email=admin%40pyregistry.local&password=wrong"))
                    .expect("request"),
            )
            .await
            .expect("second login response");
        assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn admin_rejects_bad_sessions_and_logout_expires_cookie() {
        let app = router(state().await);

        let bad_login = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/admin/login")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(
                        "email=admin%40pyregistry.local&password=wrong-password",
                    ))
                    .expect("request"),
            )
            .await
            .expect("bad login");
        assert_eq!(bad_login.status(), StatusCode::OK);
        assert!(
            body_text(bad_login)
                .await
                .contains("Invalid email or password")
        );

        let missing_cookie = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/admin/dashboard")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("missing cookie response");
        assert_eq!(missing_cookie.status(), StatusCode::UNAUTHORIZED);

        let expired_cookie = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/admin/dashboard")
                    .header(header::COOKIE, "admin_session=missing")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("expired cookie response");
        assert_eq!(expired_cookie.status(), StatusCode::UNAUTHORIZED);

        let cookie = login_cookie(app.clone()).await;
        let logout = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/admin/logout")
                    .header(header::COOKIE, cookie.clone())
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("logout response");
        assert_eq!(logout.status(), StatusCode::SEE_OTHER);

        let after_logout = app
            .oneshot(
                Request::builder()
                    .uri("/admin/dashboard")
                    .header(header::COOKIE, cookie)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("after logout response");
        assert_eq!(after_logout.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn admin_session_expiry_is_enforced_server_side() {
        let state = state().await;
        state.sessions.write().await.insert(
            "expired-session".into(),
            crate::state::StoredAdminSession {
                session: AdminSession {
                    email: "admin@pyregistry.local".into(),
                    tenant_slug: None,
                    is_superadmin: true,
                },
                expires_at: Utc::now() - chrono::Duration::minutes(1),
            },
        );
        let sessions = state.sessions.clone();
        let app = router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/admin/dashboard")
                    .header(header::COOKIE, "admin_session=expired-session")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("expired session response");

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(
            !sessions.read().await.contains_key("expired-session"),
            "expired server-side sessions should be pruned on access"
        );
    }

    #[tokio::test]
    async fn admin_posts_reject_cross_site_origins() {
        let app = router(state().await);
        let cookie = login_cookie(app.clone()).await;

        let cross_site = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/admin/logout")
                    .header(header::HOST, "registry.example.test")
                    .header(header::ORIGIN, "https://evil.example.test")
                    .header(header::COOKIE, cookie.clone())
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("cross-site response");
        assert_eq!(cross_site.status(), StatusCode::FORBIDDEN);

        let same_site = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/admin/logout")
                    .header(header::HOST, "registry.example.test")
                    .header(header::ORIGIN, "https://registry.example.test")
                    .header(header::COOKIE, cookie)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("same-site response");
        assert_eq!(same_site.status(), StatusCode::SEE_OTHER);
    }

    #[tokio::test]
    async fn admin_can_create_tenant_issue_token_register_publisher_and_reject_blank_mirror() {
        let app = router(state().await);
        let cookie = login_cookie(app.clone()).await;

        let create = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/admin/tenants")
                    .header(header::COOKIE, cookie.clone())
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(
                        "slug=omega&display_name=Omega+Corp&admin_email=admin%40omega.test&admin_password=secret&mirroring_enabled=on",
                    ))
                    .expect("request"),
            )
            .await
            .expect("create tenant");
        assert_eq!(create.status(), StatusCode::OK);
        assert!(body_text(create).await.contains("Tenant created"));

        let token = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/admin/t/omega/tokens")
                    .header(header::COOKIE, cookie.clone())
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(
                        "label=ci&ttl_hours=&scopes=read&scopes=publish&scopes=admin",
                    ))
                    .expect("request"),
            )
            .await
            .expect("token response");
        assert_eq!(token.status(), StatusCode::OK);
        let token_body = body_text(token).await;
        assert!(token_body.contains("Token issued"));
        assert!(token_body.contains("pyr_"));

        let publisher = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/admin/t/omega/publishers")
                    .header(header::COOKIE, cookie.clone())
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(
                        "project_name=demo&provider=gitlab&issuer=https%3A%2F%2Fgitlab.example&audience=pyregistry&claim_repository=omega%2Fdemo&claim_workflow=release.yml&claim_ref=refs%2Fheads%2Fmain",
                    ))
                    .expect("request"),
            )
            .await
            .expect("publisher response");
        assert_eq!(publisher.status(), StatusCode::OK);
        assert!(
            body_text(publisher)
                .await
                .contains("Trusted publisher saved")
        );

        let mirror = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/admin/t/omega/mirror-cache")
                    .header(header::COOKIE, cookie)
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from("project_name=+++"))
                    .expect("request"),
            )
            .await
            .expect("mirror response");
        assert_eq!(mirror.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn admin_can_revoke_api_tokens_by_label() {
        let state = state().await;
        let issued = state
            .app
            .issue_api_token(IssueApiTokenCommand {
                tenant_slug: "acme".into(),
                label: "ci".into(),
                scopes: vec![TokenScope::Read],
                ttl_hours: None,
            })
            .await
            .expect("token");
        state
            .app
            .authenticate_tenant_token("acme", &issued.secret, TokenScope::Read)
            .await
            .expect("token authenticates before revocation");

        let app = router(state.clone());
        let cookie = login_cookie(app.clone()).await;
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/admin/t/acme/tokens/revoke")
                    .header(header::COOKIE, cookie)
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from("label=ci"))
                    .expect("request"),
            )
            .await
            .expect("revoke response");

        assert_eq!(response.status(), StatusCode::OK);
        assert!(body_text(response).await.contains("Token revoked"));
        assert!(matches!(
            state
                .app
                .authenticate_tenant_token("acme", &issued.secret, TokenScope::Read)
                .await,
            Err(ApplicationError::Unauthorized(_))
        ));
        let audit = state
            .app
            .list_audit_trail(Some("acme"), 10)
            .await
            .expect("audit");
        assert!(audit.iter().any(|event| event.action == "api_token.revoke"));
    }

    #[tokio::test]
    async fn tenant_admin_cannot_manage_other_tenants_or_create_tenants() {
        let app = router(state().await);
        let login = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/admin/login")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(
                        "email=tenant-admin%40acme.local&password=change-me-now",
                    ))
                    .expect("request"),
            )
            .await
            .expect("tenant login");
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

        let create = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/admin/tenants")
                    .header(header::COOKIE, cookie.clone())
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(
                        "slug=beta&display_name=Beta&admin_email=admin%40beta.test&admin_password=secret",
                    ))
                    .expect("request"),
            )
            .await
            .expect("create response");
        assert_eq!(create.status(), StatusCode::FORBIDDEN);

        let token = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/admin/t/beta/tokens")
                    .header(header::COOKIE, cookie)
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from("label=ci&ttl_hours=&scopes=read"))
                    .expect("request"),
            )
            .await
            .expect("token response");
        assert_eq!(token.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn admin_search_renders_metrics_audit_and_mirror_jobs() {
        let state = state().await;
        state.mirror_jobs.write().await.insert(
            "acme:demo".into(),
            crate::state::MirrorJobStatus::queued("acme".into(), "demo".into()),
        );
        state
            .app
            .record_audit_event(pyregistry_application::RecordAuditEventCommand {
                actor: "admin@pyregistry.local".into(),
                action: "dashboard.view".into(),
                tenant_slug: Some("acme".into()),
                target: Some("demo".into()),
                metadata: HashMap::from([("source".into(), "test".into())])
                    .into_iter()
                    .collect(),
            })
            .await
            .expect("audit event");
        let app = router(state);
        let cookie = login_cookie(app.clone()).await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/admin/search?tenant=acme&q=demo")
                    .header(header::COOKIE, cookie)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("search response");

        assert_eq!(response.status(), StatusCode::OK);
        let body = body_text(response).await;
        assert!(body.contains("Queued"));
        assert!(body.contains("dashboard.view"));
    }

    #[tokio::test]
    async fn admin_mirror_cache_tracks_background_job_and_duplicate_requests() {
        let state = state().await;
        let jobs = state.mirror_jobs.clone();
        let app = router(state);
        let cookie = login_cookie(app.clone()).await;

        let started = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/admin/t/acme/mirror-cache")
                    .header(header::COOKIE, cookie.clone())
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from("project_name=Demo"))
                    .expect("request"),
            )
            .await
            .expect("mirror response");
        assert_eq!(started.status(), StatusCode::OK);
        assert!(body_text(started).await.contains("Mirror sync started"));

        for _ in 0..20 {
            let done = jobs
                .read()
                .await
                .get("acme:demo")
                .is_some_and(|job| !job.is_active());
            if done {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        assert!(
            jobs.read()
                .await
                .get("acme:demo")
                .is_some_and(|job| !job.is_active())
        );

        jobs.write().await.insert(
            "acme:demo".into(),
            crate::state::MirrorJobStatus::running("acme".into(), "Demo".into()),
        );
        let duplicate = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/admin/t/acme/mirror-cache")
                    .header(header::COOKIE, cookie)
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from("project_name=Demo"))
                    .expect("request"),
            )
            .await
            .expect("duplicate response");
        assert_eq!(duplicate.status(), StatusCode::OK);
        assert!(body_text(duplicate).await.contains("already running"));
    }

    #[tokio::test]
    async fn admin_package_governance_download_scan_and_purge_flow() {
        let state = state().await;
        let auth =
            basic_token(&issue_token(&state, vec![TokenScope::Read, TokenScope::Publish]).await);
        let app = router(state);
        upload_demo_package(app.clone(), &auth).await;
        let cookie = login_cookie(app.clone()).await;

        let detail = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/admin/t/acme/packages/demo-pkg")
                    .header(header::COOKIE, cookie.clone())
                    .header(header::HOST, "127.0.0.1:3000")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("detail response");
        assert_eq!(detail.status(), StatusCode::OK);
        let detail_body = body_text(detail).await;
        assert!(detail_body.contains("demo_pkg-1.0.0-py3-none-any.whl"));
        assert!(detail_body.contains("uv pip install"));
        assert!(detail_body.contains("Remove package"));

        let list = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/admin/t/acme/packages?q=demo")
                    .header(header::COOKIE, cookie.clone())
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("list response");
        assert_eq!(list.status(), StatusCode::OK);
        assert!(body_text(list).await.contains("Demo_Pkg"));

        let yank_release = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/admin/t/acme/packages/demo-pkg/releases/1.0.0/yank")
                    .header(header::COOKIE, cookie.clone())
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from("reason=bad+metadata"))
                    .expect("request"),
            )
            .await
            .expect("yank release");
        assert_eq!(yank_release.status(), StatusCode::SEE_OTHER);

        let unyank_release = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/admin/t/acme/packages/demo-pkg/releases/1.0.0/unyank")
                    .header(header::COOKIE, cookie.clone())
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("unyank release");
        assert_eq!(unyank_release.status(), StatusCode::SEE_OTHER);

        let yank_artifact = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/admin/t/acme/packages/demo-pkg/releases/1.0.0/artifacts/demo_pkg-1.0.0-py3-none-any.whl/yank")
                    .header(header::COOKIE, cookie.clone())
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from("reason=bad+wheel"))
                    .expect("request"),
            )
            .await
            .expect("yank artifact");
        assert_eq!(yank_artifact.status(), StatusCode::SEE_OTHER);

        let yanked_detail = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/admin/t/acme/packages/demo-pkg")
                    .header(header::COOKIE, cookie.clone())
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("yanked detail");
        assert_eq!(yanked_detail.status(), StatusCode::OK);
        assert!(body_text(yanked_detail).await.contains("File is yanked"));

        let unyank_artifact = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/admin/t/acme/packages/demo-pkg/releases/1.0.0/artifacts/demo_pkg-1.0.0-py3-none-any.whl/unyank")
                    .header(header::COOKIE, cookie.clone())
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("unyank artifact");
        assert_eq!(unyank_artifact.status(), StatusCode::SEE_OTHER);

        let download = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/admin/t/acme/packages/demo-pkg/releases/1.0.0/artifacts/demo_pkg-1.0.0-py3-none-any.whl/download")
                    .header(header::COOKIE, cookie.clone())
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("admin download");
        assert_eq!(download.status(), StatusCode::OK);
        assert_eq!(
            download.headers().get(header::CONTENT_DISPOSITION).unwrap(),
            "attachment; filename=\"demo_pkg-1.0.0-py3-none-any.whl\""
        );
        assert_eq!(body_text(download).await, "fake wheel bytes");

        let scan = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/admin/t/acme/packages/demo-pkg/releases/1.0.0/artifacts/demo_pkg-1.0.0-py3-none-any.whl/scan")
                    .header(header::COOKIE, cookie.clone())
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("scan response");
        assert_eq!(scan.status(), StatusCode::OK);
        assert!(body_text(scan).await.contains("Wheel audit"));

        let purge_artifact = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/admin/t/acme/packages/demo-pkg/releases/1.0.0/artifacts/demo_pkg-1.0.0-py3-none-any.whl/purge")
                    .header(header::COOKIE, cookie.clone())
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("purge artifact");
        assert_eq!(purge_artifact.status(), StatusCode::SEE_OTHER);

        upload_demo_package(app.clone(), &auth).await;
        let purge_release = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/admin/t/acme/packages/demo-pkg/releases/1.0.0/purge")
                    .header(header::COOKIE, cookie.clone())
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("purge release");
        assert_eq!(purge_release.status(), StatusCode::SEE_OTHER);

        upload_demo_package(app.clone(), &auth).await;
        let remove_package = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/admin/t/acme/packages/demo-pkg/remove")
                    .header(header::COOKIE, cookie.clone())
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("remove package");
        assert_eq!(remove_package.status(), StatusCode::SEE_OTHER);

        let removed_detail = app
            .oneshot(
                Request::builder()
                    .uri("/admin/t/acme/packages/demo-pkg")
                    .header(header::COOKIE, cookie)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("removed detail");
        assert_eq!(removed_detail.status(), StatusCode::NOT_FOUND);
    }
}
