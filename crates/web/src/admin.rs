use crate::{
    audit::{audit_metadata, record_audit_event},
    auth::{ensure_tenant_access, human_bytes, parse_scopes, require_session},
    error::{WebError, render_html},
    models::{
        ArtifactSecurityView, AuditTrailEntryView, AuditTrailMetadataView, CreateTenantFormData,
        DashboardTemplate, DashboardView, DependencyVulnerabilityFindingView,
        DependencyVulnerabilityView, IndexTemplate, IssueTokenFormData, LoginFormData,
        LoginTemplate, MessageTemplate, MirrorFormData, MirrorJobView, PackageArtifactView,
        PackageDetailTemplate, PackageDetailView, PackageReleaseView, PackageSecuritySummaryView,
        PackageVulnerabilityView, PublisherFormData, RevokeTokenFormData, SearchQuery, TenantView,
        WheelAuditResponse, YankFormData,
    },
    state::{AppState, MirrorJobPhase, MirrorJobStatus, mirror_job_key},
};
use axum::{
    Form, Json,
    body::{Body, Bytes},
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{Html, IntoResponse, Redirect, Response},
};
use axum_extra::extract::cookie::{Cookie, CookieJar};
use log::{debug, info, warn};
use pyregistry_application::{
    AdminSession, ApplicationError, AuditStoredWheelCommand, CreateTenantCommand, DeletionCommand,
    IssueApiTokenCommand, RegisterTrustedPublisherCommand, WheelAuditFinding,
    WheelAuditFindingKind, WheelAuditReport,
};
use pyregistry_domain::{DeletionMode, TokenScope, TrustedPublisherProvider};
use std::collections::HashMap;
use std::fmt::Write;

pub(crate) async fn index(State(state): State<AppState>) -> Result<Html<String>, WebError> {
    let overview = state.app.get_registry_overview().await?;
    debug!(
        "rendering public index page with tenants={}, projects={}, artifacts={}",
        overview.tenant_count, overview.project_count, overview.artifact_count
    );
    render_html(IndexTemplate {
        total_storage_human: human_bytes(overview.total_storage_bytes),
        overview,
        show_stats: state.show_index_stats,
    })
}

pub(crate) async fn login_form() -> Result<Html<String>, WebError> {
    render_html(LoginTemplate { error: None })
}

pub(crate) async fn login_submit(
    State(state): State<AppState>,
    jar: CookieJar,
    Form(form): Form<LoginFormData>,
) -> Result<impl IntoResponse, WebError> {
    info!("admin login form submitted for `{}`", form.email.trim());
    match state.app.login_admin(&form.email, &form.password).await {
        Ok(session) => {
            let session_id = uuid::Uuid::new_v4().to_string();
            info!(
                "admin session established for `{}` (superadmin={}, tenant={:?})",
                session.email, session.is_superadmin, session.tenant_slug
            );
            state
                .sessions
                .write()
                .await
                .insert(session_id.clone(), session.clone());
            record_audit_event(
                &state,
                session.email.clone(),
                "admin.login",
                session.tenant_slug.clone(),
                Some(session.email.clone()),
                audit_metadata([
                    ("superadmin", session.is_superadmin.to_string()),
                    (
                        "tenant",
                        session
                            .tenant_slug
                            .clone()
                            .unwrap_or_else(|| "global".into()),
                    ),
                ]),
            )
            .await;
            let cookie = Cookie::build(("admin_session", session_id))
                .path("/")
                .http_only(true)
                .build();
            Ok((jar.add(cookie), Redirect::to("/admin/dashboard")).into_response())
        }
        Err(ApplicationError::Unauthorized(_)) => {
            warn!("admin login failed for `{}`", form.email.trim());
            render_html(LoginTemplate {
                error: Some("Invalid email or password"),
            })
            .map(IntoResponse::into_response)
        }
        Err(error) => Err(error.into()),
    }
}

pub(crate) async fn logout(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<impl IntoResponse, WebError> {
    let removed_session = if let Some(cookie) = jar.get("admin_session") {
        state.sessions.write().await.remove(cookie.value())
    } else {
        None
    };
    if let Some(session) = removed_session {
        record_audit_event(
            &state,
            session.email.clone(),
            "admin.logout",
            session.tenant_slug.clone(),
            Some(session.email),
            audit_metadata([]),
        )
        .await;
        info!("admin session removed");
    }
    let mut expired = Cookie::from("admin_session=");
    expired.set_path("/");
    expired.make_removal();
    Ok((jar.remove(expired), Redirect::to("/admin/login")))
}

pub(crate) async fn dashboard(
    State(state): State<AppState>,
    jar: CookieJar,
    Query(query): Query<SearchQuery>,
) -> Result<Html<String>, WebError> {
    let session = require_session(&state, &jar).await?;
    debug!(
        "rendering dashboard for `{}` with selected tenant {:?} and query {:?}",
        session.email, query.tenant, query.q
    );
    render_dashboard(&state, session, query).await
}

pub(crate) async fn search(
    State(state): State<AppState>,
    jar: CookieJar,
    Query(query): Query<SearchQuery>,
) -> Result<Html<String>, WebError> {
    let session = require_session(&state, &jar).await?;
    info!(
        "admin search requested by `{}` for tenant {:?} query {:?}",
        session.email, query.tenant, query.q
    );
    render_dashboard(&state, session, query).await
}

pub(crate) async fn create_tenant(
    State(state): State<AppState>,
    jar: CookieJar,
    Form(form): Form<CreateTenantFormData>,
) -> Result<Html<String>, WebError> {
    let session = require_session(&state, &jar).await?;
    if !session.is_superadmin {
        warn!(
            "tenant creation denied because `{}` is not a superadmin",
            session.email
        );
        return Err(WebError {
            status: StatusCode::FORBIDDEN,
            message: "Only superadmins can create tenants".into(),
        });
    }
    info!(
        "superadmin `{}` is creating tenant `{}`",
        session.email, form.slug
    );
    let slug = form.slug.clone();
    let display_name = form.display_name.clone();
    let admin_email = form.admin_email.clone();
    let mirroring_enabled = form.mirroring_enabled.is_some();

    let tenant = state
        .app
        .create_tenant(CreateTenantCommand {
            slug: form.slug,
            display_name: form.display_name,
            mirroring_enabled,
            admin_email: form.admin_email,
            admin_password: form.admin_password,
        })
        .await?;
    record_audit_event(
        &state,
        session.email,
        "tenant.create",
        Some(tenant.slug.as_str().to_string()),
        Some(slug),
        audit_metadata([
            ("display_name", display_name),
            ("admin_email", admin_email),
            ("mirroring_enabled", mirroring_enabled.to_string()),
        ]),
    )
    .await;

    render_html(MessageTemplate {
        title: "Tenant created",
        message: &format!(
            "Tenant `{}` is ready. The admin account can now sign in from the login page.",
            tenant.slug.as_str()
        ),
        back_href: "/admin/dashboard",
    })
}

pub(crate) async fn issue_token(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(tenant): Path<String>,
    body: Bytes,
) -> Result<Html<String>, WebError> {
    let session = require_session(&state, &jar).await?;
    ensure_tenant_access(&session, &tenant)?;
    let form = parse_issue_token_form(&body)?;
    let ttl_hours = parse_optional_ttl_hours(form.ttl_hours.as_deref())?;
    info!(
        "admin `{}` is issuing token `{}` for tenant `{}`",
        session.email, form.label, tenant
    );
    let label = form.label.clone();
    let scopes = parse_scopes(form.scopes);
    let scope_summary = scopes
        .iter()
        .map(token_scope_label)
        .collect::<Vec<_>>()
        .join(",");
    let token = state
        .app
        .issue_api_token(IssueApiTokenCommand {
            tenant_slug: tenant.clone(),
            label: form.label,
            scopes,
            ttl_hours,
        })
        .await?;
    record_audit_event(
        &state,
        session.email,
        "api_token.issue",
        Some(tenant.clone()),
        Some(label),
        audit_metadata([
            ("scopes", scope_summary),
            (
                "ttl_hours",
                ttl_hours
                    .map(|ttl| ttl.to_string())
                    .unwrap_or_else(|| "none".into()),
            ),
        ]),
    )
    .await;

    render_html(MessageTemplate {
        title: "Token issued",
        message: &format!("New token `{}`: {}", token.label, token.secret),
        back_href: &format!("/admin/t/{tenant}/packages"),
    })
}

pub(crate) async fn revoke_token(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(tenant): Path<String>,
    Form(form): Form<RevokeTokenFormData>,
) -> Result<Html<String>, WebError> {
    let session = require_session(&state, &jar).await?;
    ensure_tenant_access(&session, &tenant)?;
    let label = form.label.trim().to_string();
    if label.is_empty() {
        return Err(WebError {
            status: StatusCode::BAD_REQUEST,
            message: "Token label cannot be empty".into(),
        });
    }

    info!(
        "admin `{}` is revoking token `{}` for tenant `{}`",
        session.email, label, tenant
    );
    state.app.revoke_api_token(&tenant, &label).await?;
    record_audit_event(
        &state,
        session.email,
        "api_token.revoke",
        Some(tenant.clone()),
        Some(label.clone()),
        audit_metadata([("label", label.clone())]),
    )
    .await;

    render_html(MessageTemplate {
        title: "Token revoked",
        message: &format!("Token `{label}` can no longer access this tenant."),
        back_href: &format!("/admin/search?tenant={tenant}"),
    })
}

pub(crate) async fn cache_mirror_project(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(tenant): Path<String>,
    Form(form): Form<MirrorFormData>,
) -> Result<Html<String>, WebError> {
    let session = require_session(&state, &jar).await?;
    ensure_tenant_access(&session, &tenant)?;
    let project_name = form.project_name.trim().to_string();
    if project_name.is_empty() {
        return Err(WebError {
            status: StatusCode::BAD_REQUEST,
            message: "Project name cannot be empty".into(),
        });
    }
    info!(
        "admin `{}` requested mirror cache refresh for tenant `{}` project `{}`",
        session.email, tenant, project_name
    );
    let key = mirror_job_key(&tenant, &project_name);
    {
        let jobs = state.mirror_jobs.read().await;
        if jobs.get(&key).is_some_and(MirrorJobStatus::is_active) {
            let message = format!(
                "A background mirror sync for `{project_name}` is already running. You can return to the dashboard and watch the status update there."
            );
            let back_href = format!("/admin/search?tenant={tenant}");
            return render_html(MessageTemplate {
                title: "Mirror sync already running",
                message: &message,
                back_href: &back_href,
            });
        }
    }

    {
        let mut jobs = state.mirror_jobs.write().await;
        jobs.insert(
            key.clone(),
            MirrorJobStatus::queued(tenant.clone(), project_name.clone()),
        );
    }
    record_audit_event(
        &state,
        session.email,
        "mirror.refresh.request",
        Some(tenant.clone()),
        Some(project_name.clone()),
        audit_metadata([("project", project_name.clone())]),
    )
    .await;

    let app = state.app.clone();
    let mirror_jobs = state.mirror_jobs.clone();
    let tenant_for_task = tenant.clone();
    let project_for_task = project_name.clone();
    tokio::spawn(async move {
        {
            let mut jobs = mirror_jobs.write().await;
            jobs.insert(
                key.clone(),
                MirrorJobStatus::running(tenant_for_task.clone(), project_for_task.clone()),
            );
        }

        let next_status = match app
            .resolve_project_from_mirror(&tenant_for_task, &project_for_task)
            .await
        {
            Ok(Some(project)) => MirrorJobStatus::completed(
                tenant_for_task.clone(),
                project_for_task.clone(),
                format!(
                    "Mirrored `{}` and cached all currently available upstream files.",
                    project.name.original()
                ),
            ),
            Ok(None) => MirrorJobStatus::failed(
                tenant_for_task.clone(),
                project_for_task.clone(),
                format!("PyPI package `{project_for_task}` was not found."),
            ),
            Err(error) => MirrorJobStatus::failed(
                tenant_for_task.clone(),
                project_for_task.clone(),
                error.to_string(),
            ),
        };

        let mut jobs = mirror_jobs.write().await;
        jobs.insert(key, next_status);
    });

    let message = format!(
        "Started a background mirror sync for `{project_name}`. The dashboard will stay responsive while Pyregistry downloads metadata and all available files from PyPI."
    );
    let back_href = format!("/admin/search?tenant={tenant}");

    render_html(MessageTemplate {
        title: "Mirror sync started",
        message: &message,
        back_href: &back_href,
    })
}

pub(crate) async fn register_publisher(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(tenant): Path<String>,
    Form(form): Form<PublisherFormData>,
) -> Result<Html<String>, WebError> {
    let session = require_session(&state, &jar).await?;
    ensure_tenant_access(&session, &tenant)?;
    info!(
        "admin `{}` is registering a trusted publisher for tenant `{}` project `{}`",
        session.email, tenant, form.project_name
    );

    let provider = if form.provider.eq_ignore_ascii_case("github") {
        TrustedPublisherProvider::GitHubActions
    } else {
        TrustedPublisherProvider::GitLab
    };
    let provider_label = format!("{provider:?}");
    let project_name = form.project_name.clone();
    let issuer = form.issuer.clone();
    let mut claim_rules = HashMap::new();
    if let Some(value) = form.claim_repository.filter(|value| !value.is_empty()) {
        claim_rules.insert("repository".to_string(), value);
    }
    if let Some(value) = form.claim_workflow.filter(|value| !value.is_empty()) {
        claim_rules.insert("workflow".to_string(), value);
    }
    if let Some(value) = form.claim_ref.filter(|value| !value.is_empty()) {
        claim_rules.insert("ref".to_string(), value);
    }

    state
        .app
        .register_trusted_publisher(RegisterTrustedPublisherCommand {
            tenant_slug: tenant.clone(),
            project_name: form.project_name,
            provider,
            issuer: form.issuer,
            audience: form.audience,
            claim_rules: claim_rules.into_iter().collect(),
        })
        .await?;
    record_audit_event(
        &state,
        session.email,
        "trusted_publisher.register",
        Some(tenant.clone()),
        Some(project_name.clone()),
        audit_metadata([
            ("project", project_name),
            ("provider", provider_label),
            ("issuer", issuer),
        ]),
    )
    .await;

    render_html(MessageTemplate {
        title: "Trusted publisher saved",
        message: "The OIDC publisher configuration is now active for this tenant.",
        back_href: &format!("/admin/t/{tenant}/packages"),
    })
}

pub(crate) async fn package_list(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(tenant): Path<String>,
    Query(query): Query<SearchQuery>,
) -> Result<Html<String>, WebError> {
    let session = require_session(&state, &jar).await?;
    ensure_tenant_access(&session, &tenant)?;
    debug!(
        "rendering package list for tenant `{}` requested by `{}` with query {:?}",
        tenant, session.email, query.q
    );
    render_dashboard(
        &state,
        session,
        SearchQuery {
            tenant: Some(tenant),
            q: query.q,
        },
    )
    .await
}

pub(crate) async fn package_detail(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Path((tenant, project)): Path<(String, String)>,
) -> Result<Html<String>, WebError> {
    let session = require_session(&state, &jar).await?;
    ensure_tenant_access(&session, &tenant)?;
    info!(
        "admin `{}` is viewing package `{}` in tenant `{}`",
        session.email, project, tenant
    );
    let install_base_url = registry_base_url(&headers);
    let details = package_detail_view(
        state.app.get_package_details(&tenant, &project).await?,
        &install_base_url,
    );
    render_html(PackageDetailTemplate { details })
}

pub(crate) async fn remove_package(
    State(state): State<AppState>,
    jar: CookieJar,
    Path((tenant, project)): Path<(String, String)>,
) -> Result<impl IntoResponse, WebError> {
    let session = require_session(&state, &jar).await?;
    ensure_tenant_access(&session, &tenant)?;
    info!(
        "admin `{}` is removing package `{}` in tenant `{}`",
        session.email, project, tenant
    );
    state.app.remove_package(&tenant, &project).await?;
    record_audit_event(
        &state,
        session.email,
        "package.remove",
        Some(tenant.clone()),
        Some(project.clone()),
        audit_metadata([]),
    )
    .await;
    Ok(Redirect::to(&format!("/admin/t/{tenant}/packages")))
}

pub(crate) async fn yank_release(
    State(state): State<AppState>,
    jar: CookieJar,
    Path((tenant, project, version)): Path<(String, String, String)>,
    Form(form): Form<YankFormData>,
) -> Result<impl IntoResponse, WebError> {
    let session = require_session(&state, &jar).await?;
    ensure_tenant_access(&session, &tenant)?;
    info!(
        "admin `{}` is yanking release `{}` for package `{}` in tenant `{}`",
        session.email, version, project, tenant
    );
    let reason = form.reason.clone();
    state
        .app
        .yank_release(DeletionCommand {
            tenant_slug: tenant.clone(),
            project_name: project.clone(),
            version: Some(version.clone()),
            filename: None,
            reason,
            mode: DeletionMode::Yank,
        })
        .await?;
    record_audit_event(
        &state,
        session.email,
        "release.yank",
        Some(tenant.clone()),
        Some(format!("{project}/{version}")),
        audit_metadata([("reason", form.reason.unwrap_or_default())]),
    )
    .await;
    Ok(Redirect::to(&format!(
        "/admin/t/{tenant}/packages/{project}"
    )))
}

pub(crate) async fn unyank_release(
    State(state): State<AppState>,
    jar: CookieJar,
    Path((tenant, project, version)): Path<(String, String, String)>,
) -> Result<impl IntoResponse, WebError> {
    let session = require_session(&state, &jar).await?;
    ensure_tenant_access(&session, &tenant)?;
    info!(
        "admin `{}` is unyanking release `{}` for package `{}` in tenant `{}`",
        session.email, version, project, tenant
    );
    state
        .app
        .unyank_release(&tenant, &project, &version)
        .await?;
    record_audit_event(
        &state,
        session.email,
        "release.unyank",
        Some(tenant.clone()),
        Some(format!("{project}/{version}")),
        audit_metadata([]),
    )
    .await;
    Ok(Redirect::to(&format!(
        "/admin/t/{tenant}/packages/{project}"
    )))
}

pub(crate) async fn purge_release(
    State(state): State<AppState>,
    jar: CookieJar,
    Path((tenant, project, version)): Path<(String, String, String)>,
) -> Result<impl IntoResponse, WebError> {
    let session = require_session(&state, &jar).await?;
    ensure_tenant_access(&session, &tenant)?;
    info!(
        "admin `{}` is purging release `{}` for package `{}` in tenant `{}`",
        session.email, version, project, tenant
    );
    state.app.purge_release(&tenant, &project, &version).await?;
    record_audit_event(
        &state,
        session.email,
        "release.purge",
        Some(tenant.clone()),
        Some(format!("{project}/{version}")),
        audit_metadata([]),
    )
    .await;
    Ok(Redirect::to(&format!(
        "/admin/t/{tenant}/packages/{project}"
    )))
}

pub(crate) async fn yank_artifact(
    State(state): State<AppState>,
    jar: CookieJar,
    Path((tenant, project, version, filename)): Path<(String, String, String, String)>,
    Form(form): Form<YankFormData>,
) -> Result<impl IntoResponse, WebError> {
    let session = require_session(&state, &jar).await?;
    ensure_tenant_access(&session, &tenant)?;
    info!(
        "admin `{}` is yanking artifact `{}` for package `{}` version `{}` in tenant `{}`",
        session.email, filename, project, version, tenant
    );
    let reason = form.reason.clone();
    state
        .app
        .yank_artifact(DeletionCommand {
            tenant_slug: tenant.clone(),
            project_name: project.clone(),
            version: Some(version.clone()),
            filename: Some(filename.clone()),
            reason,
            mode: DeletionMode::Yank,
        })
        .await?;
    record_audit_event(
        &state,
        session.email,
        "artifact.yank",
        Some(tenant.clone()),
        Some(format!("{project}/{version}/{filename}")),
        audit_metadata([("reason", form.reason.unwrap_or_default())]),
    )
    .await;
    Ok(Redirect::to(&format!(
        "/admin/t/{tenant}/packages/{project}"
    )))
}

pub(crate) async fn unyank_artifact(
    State(state): State<AppState>,
    jar: CookieJar,
    Path((tenant, project, version, filename)): Path<(String, String, String, String)>,
) -> Result<impl IntoResponse, WebError> {
    let session = require_session(&state, &jar).await?;
    ensure_tenant_access(&session, &tenant)?;
    info!(
        "admin `{}` is unyanking artifact `{}` for package `{}` version `{}` in tenant `{}`",
        session.email, filename, project, version, tenant
    );
    state
        .app
        .unyank_artifact(&tenant, &project, &version, &filename)
        .await?;
    record_audit_event(
        &state,
        session.email,
        "artifact.unyank",
        Some(tenant.clone()),
        Some(format!("{project}/{version}/{filename}")),
        audit_metadata([]),
    )
    .await;
    Ok(Redirect::to(&format!(
        "/admin/t/{tenant}/packages/{project}"
    )))
}

pub(crate) async fn purge_artifact(
    State(state): State<AppState>,
    jar: CookieJar,
    Path((tenant, project, version, filename)): Path<(String, String, String, String)>,
) -> Result<impl IntoResponse, WebError> {
    let session = require_session(&state, &jar).await?;
    ensure_tenant_access(&session, &tenant)?;
    info!(
        "admin `{}` is purging artifact `{}` for package `{}` version `{}` in tenant `{}`",
        session.email, filename, project, version, tenant
    );
    state
        .app
        .purge_artifact(&tenant, &project, &version, &filename)
        .await?;
    record_audit_event(
        &state,
        session.email,
        "artifact.purge",
        Some(tenant.clone()),
        Some(format!("{project}/{version}/{filename}")),
        audit_metadata([]),
    )
    .await;
    Ok(Redirect::to(&format!(
        "/admin/t/{tenant}/packages/{project}"
    )))
}

pub(crate) async fn download_artifact(
    State(state): State<AppState>,
    jar: CookieJar,
    Path((tenant, project, version, filename)): Path<(String, String, String, String)>,
) -> Result<Response, WebError> {
    let session = require_session(&state, &jar).await?;
    ensure_tenant_access(&session, &tenant)?;
    info!(
        "admin `{}` is downloading artifact `{}` for package `{}` version `{}` in tenant `{}`",
        session.email, filename, project, version, tenant
    );

    let bytes = state
        .app
        .download_artifact(&tenant, &project, &version, &filename)
        .await?;
    record_audit_event(
        &state,
        session.email,
        "artifact.download",
        Some(tenant.clone()),
        Some(format!("{project}/{version}/{filename}")),
        audit_metadata([
            ("project", project),
            ("version", version),
            ("filename", filename.clone()),
            ("bytes", bytes.len().to_string()),
        ]),
    )
    .await;
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(header::CONTENT_LENGTH, bytes.len().to_string())
        .header(
            header::CONTENT_DISPOSITION,
            attachment_content_disposition(&filename),
        )
        .body(Body::from(bytes))
        .expect("valid artifact download response"))
}

pub(crate) async fn scan_artifact(
    State(state): State<AppState>,
    jar: CookieJar,
    Path((tenant, project, version, filename)): Path<(String, String, String, String)>,
) -> Result<Json<WheelAuditResponse>, WebError> {
    let session = require_session(&state, &jar).await?;
    ensure_tenant_access(&session, &tenant)?;
    info!(
        "admin `{}` requested wheel scan for `{}` package `{}` version `{}` in tenant `{}`",
        session.email, filename, project, version, tenant
    );

    let report = state
        .app
        .audit_stored_wheel(AuditStoredWheelCommand {
            tenant_slug: tenant.clone(),
            project_name: project.clone(),
            version: version.clone(),
            filename: filename.clone(),
        })
        .await?;
    record_audit_event(
        &state,
        session.email,
        "artifact.scan",
        Some(tenant),
        Some(format!("{project}/{version}/{filename}")),
        audit_metadata([
            ("project", project),
            ("version", version),
            ("filename", filename),
            ("findings", report.findings.len().to_string()),
        ]),
    )
    .await;
    Ok(Json(WheelAuditResponse {
        artifact_filename: report.wheel_filename.clone(),
        report_text: format_wheel_audit_report_text(&report),
    }))
}

async fn render_dashboard(
    state: &AppState,
    session: AdminSession,
    query: SearchQuery,
) -> Result<Html<String>, WebError> {
    debug!(
        "assembling dashboard view for `{}` tenant_hint={:?} query={:?}",
        session.email, query.tenant, query.q
    );
    let overview = state.app.get_registry_overview().await?;
    let tenants = state
        .app
        .list_tenants()
        .await?
        .into_iter()
        .map(|tenant| TenantView {
            slug: tenant.slug.as_str().to_string(),
            display_name: tenant.display_name,
            mirroring_enabled: tenant.mirror_rule.enabled,
        })
        .collect::<Vec<_>>();

    let selected_tenant = session
        .tenant_slug
        .clone()
        .or(query.tenant.clone())
        .or_else(|| tenants.first().map(|tenant| tenant.slug.clone()));
    let metrics = if let Some(ref tenant_slug) = selected_tenant {
        let metrics = state.app.get_tenant_dashboard(tenant_slug).await?;
        Some(DashboardView {
            tenant_slug: metrics.tenant_slug,
            project_count: metrics.project_count,
            release_count: metrics.release_count,
            artifact_count: metrics.artifact_count,
            token_count: metrics.token_count,
            trusted_publisher_count: metrics.trusted_publisher_count,
        })
    } else {
        None
    };

    let search_query = query.q.unwrap_or_default();
    let search_results = if let Some(ref tenant_slug) = selected_tenant {
        state
            .app
            .search_packages(tenant_slug, &search_query)
            .await?
    } else {
        Vec::new()
    };
    let mut mirror_jobs = if let Some(ref tenant_slug) = selected_tenant {
        state
            .mirror_jobs
            .read()
            .await
            .values()
            .filter(|job| job.tenant_slug == *tenant_slug)
            .map(|job| MirrorJobView {
                project_name: job.project_name.clone(),
                status_label: mirror_job_label(job.phase).to_string(),
                detail: job.detail.clone(),
                active: matches!(job.phase, MirrorJobPhase::Queued | MirrorJobPhase::Running),
            })
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    mirror_jobs.sort_by(|left, right| {
        right
            .active
            .cmp(&left.active)
            .then(left.project_name.cmp(&right.project_name))
    });
    let audit_events = state
        .app
        .list_audit_trail(selected_tenant.as_deref(), 25)
        .await?
        .into_iter()
        .map(audit_trail_entry_view)
        .collect::<Vec<_>>();
    let total_storage_human = human_bytes(overview.total_storage_bytes);

    debug!(
        "dashboard view ready for `{}` with {} tenant option(s), {} search result(s), {} mirror job(s), and {} audit event(s)",
        session.email,
        tenants.len(),
        search_results.len(),
        mirror_jobs.len(),
        audit_events.len()
    );
    render_html(DashboardTemplate {
        overview,
        total_storage_human,
        tenants,
        selected_tenant,
        metrics,
        mirror_jobs,
        audit_events,
        search_query,
        search_results,
        session,
    })
}

fn mirror_job_label(phase: MirrorJobPhase) -> &'static str {
    match phase {
        MirrorJobPhase::Queued => "Queued",
        MirrorJobPhase::Running => "Running",
        MirrorJobPhase::Completed => "Completed",
        MirrorJobPhase::Failed => "Failed",
    }
}

fn audit_trail_entry_view(entry: pyregistry_application::AuditTrailEntry) -> AuditTrailEntryView {
    AuditTrailEntryView {
        occurred_at: entry
            .occurred_at
            .format("%Y-%m-%d %H:%M:%S UTC")
            .to_string(),
        actor: entry.actor,
        action: entry.action,
        tenant_slug: entry.tenant_slug,
        target: entry.target,
        metadata: entry
            .metadata
            .into_iter()
            .map(|(key, value)| AuditTrailMetadataView { key, value })
            .collect(),
    }
}

fn token_scope_label(scope: &TokenScope) -> &'static str {
    match scope {
        TokenScope::Read => "read",
        TokenScope::Publish => "publish",
        TokenScope::Admin => "admin",
    }
}

fn parse_optional_ttl_hours(raw: Option<&str>) -> Result<Option<i64>, WebError> {
    let Some(raw) = raw.map(str::trim).filter(|raw| !raw.is_empty()) else {
        return Ok(None);
    };

    let ttl_hours = raw.parse::<i64>().map_err(|_| WebError {
        status: StatusCode::BAD_REQUEST,
        message: "TTL hours must be a whole number".into(),
    })?;
    Ok(Some(ttl_hours))
}

fn parse_issue_token_form(raw_form: &[u8]) -> Result<IssueTokenFormData, WebError> {
    let mut label = None;
    let mut ttl_hours = None;
    let mut scopes = Vec::new();

    for (key, value) in url::form_urlencoded::parse(raw_form) {
        match key.as_ref() {
            "label" => label = Some(value.into_owned()),
            "ttl_hours" => ttl_hours = Some(value.into_owned()),
            "scopes" => scopes.push(value.into_owned()),
            _ => {}
        }
    }

    let label = label
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| WebError {
            status: StatusCode::BAD_REQUEST,
            message: "Token label cannot be empty".into(),
        })?;

    Ok(IssueTokenFormData {
        label,
        ttl_hours,
        scopes,
    })
}

fn package_detail_view(
    details: pyregistry_application::PackageDetails,
    install_base_url: &str,
) -> PackageDetailView {
    let tenant_slug = details.tenant_slug.clone();
    let normalized_name = details.normalized_name.clone();
    let project_name = details.project_name.clone();
    let base_url = install_base_url.trim_end_matches('/');
    let index_url = format!("{base_url}/t/{tenant_slug}/simple/");
    let pip_install_command = install_command("pip install", &index_url, &project_name);
    let uv_install_command = install_command("uv pip install", &index_url, &project_name);
    let scan_unavailable =
        is_pysentry_package_scan_unavailable(details.security.scan_error.as_deref());
    let dependency_scan_unavailable =
        is_pysentry_dependency_scan_unavailable(details.security.dependency_scan_error.as_deref());
    let dependency_findings = dependency_findings_view(&details.releases);

    PackageDetailView {
        tenant_slug: details.tenant_slug,
        project_name: details.project_name,
        normalized_name: details.normalized_name,
        summary: details.summary,
        description: details.description,
        source: details.source,
        index_url,
        security: PackageSecuritySummaryView {
            scanned_file_count: details.security.scanned_file_count,
            vulnerable_file_count: details.security.vulnerable_file_count,
            vulnerability_count: details.security.vulnerability_count,
            highest_severity: details.security.highest_severity,
            scan_unavailable,
            scan_error: package_scan_error_view(details.security.scan_error, scan_unavailable),
            scanned_dependency_count: details.security.scanned_dependency_count,
            vulnerable_dependency_count: details.security.vulnerable_dependency_count,
            dependency_vulnerability_count: details.security.dependency_vulnerability_count,
            dependency_findings,
            dependency_scan_unavailable,
            dependency_scan_error: dependency_scan_error_view(
                details.security.dependency_scan_error,
                dependency_scan_unavailable,
            ),
        },
        pip_install_command,
        uv_install_command,
        releases: details
            .releases
            .into_iter()
            .enumerate()
            .map(|(index, release)| {
                let release_version = release.version.clone();
                let artifact_count = release.artifacts.len();
                let total_size_bytes = release
                    .artifacts
                    .iter()
                    .map(|artifact| artifact.size_bytes)
                    .sum();

                PackageReleaseView {
                    version: release.version,
                    yanked_reason: release.yanked_reason,
                    artifact_count,
                    total_size_human: human_bytes(total_size_bytes),
                    expanded: index == 0,
                    artifacts: release
                        .artifacts
                        .into_iter()
                        .map(|artifact| PackageArtifactView {
                            is_wheel: artifact.filename.ends_with(".whl"),
                            download_url: format!(
                                "/admin/t/{}/packages/{}/releases/{}/artifacts/{}/download",
                                tenant_slug, normalized_name, release_version, artifact.filename
                            ),
                            scan_url: format!(
                                "/admin/t/{}/packages/{}/releases/{}/artifacts/{}/scan",
                                tenant_slug, normalized_name, release_version, artifact.filename
                            ),
                            filename: artifact.filename,
                            size_human: human_bytes(artifact.size_bytes),
                            sha256: artifact.sha256,
                            yanked_reason: artifact.yanked_reason,
                            security: artifact_security_view(artifact.security),
                        })
                        .collect(),
                }
            })
            .collect(),
        trusted_publishers: details.trusted_publishers,
    }
}

const PYSENTRY_PACKAGE_LOOKUP_UNAVAILABLE: &str =
    "PySentry vulnerability lookup is unavailable on Windows GNU targets";
const PYSENTRY_DEPENDENCY_LOOKUP_UNAVAILABLE: &str =
    "PySentry dependency vulnerability lookup is unavailable on Windows GNU targets";

fn is_pysentry_package_scan_unavailable(error: Option<&str>) -> bool {
    all_scan_errors_are(error, PYSENTRY_PACKAGE_LOOKUP_UNAVAILABLE)
}

fn is_pysentry_dependency_scan_unavailable(error: Option<&str>) -> bool {
    all_scan_errors_are(error, PYSENTRY_DEPENDENCY_LOOKUP_UNAVAILABLE)
}

fn all_scan_errors_are(error: Option<&str>, expected: &str) -> bool {
    let Some(error) = error else {
        return false;
    };
    !error.trim().is_empty()
        && error
            .split(';')
            .map(str::trim)
            .all(|message| message.contains(expected))
}

fn package_scan_error_view(error: Option<String>, unavailable: bool) -> Option<String> {
    if unavailable {
        Some(PYSENTRY_PACKAGE_LOOKUP_UNAVAILABLE.into())
    } else {
        error
    }
}

fn dependency_scan_error_view(error: Option<String>, unavailable: bool) -> Option<String> {
    if unavailable {
        Some(PYSENTRY_DEPENDENCY_LOOKUP_UNAVAILABLE.into())
    } else {
        error
    }
}

fn artifact_security_view(
    security: pyregistry_application::ArtifactSecurityDetails,
) -> ArtifactSecurityView {
    let vulnerability_count = security.vulnerability_count;
    let vulnerabilities = security
        .vulnerabilities
        .into_iter()
        .take(3)
        .map(|vulnerability| package_vulnerability_view(vulnerability, "no fixed version listed"))
        .collect::<Vec<_>>();
    let hidden_vulnerability_count = vulnerability_count.saturating_sub(vulnerabilities.len());
    let dependencies = security
        .dependencies
        .into_iter()
        .map(dependency_vulnerability_view)
        .collect();

    ArtifactSecurityView {
        scanned: security.scanned,
        vulnerability_count,
        highest_severity: security.highest_severity,
        vulnerabilities,
        hidden_vulnerability_count,
        scan_error: security.scan_error,
        dependency_count: security.dependency_count,
        vulnerable_dependency_count: security.vulnerable_dependency_count,
        dependency_vulnerability_count: security.dependency_vulnerability_count,
        dependencies,
        dependency_scan_error: security.dependency_scan_error,
    }
}

fn dependency_findings_view(
    releases: &[pyregistry_application::PackageReleaseDetails],
) -> Vec<DependencyVulnerabilityFindingView> {
    releases
        .iter()
        .flat_map(|release| {
            release.artifacts.iter().flat_map(|artifact| {
                artifact
                    .security
                    .dependencies
                    .iter()
                    .filter(|dependency| dependency.vulnerability_count > 0)
                    .cloned()
                    .map(|dependency| DependencyVulnerabilityFindingView {
                        artifact_filename: artifact.filename.clone(),
                        dependency: dependency_vulnerability_view(dependency),
                    })
            })
        })
        .collect()
}

fn dependency_vulnerability_view(
    dependency: pyregistry_application::DependencyVulnerabilityDetails,
) -> DependencyVulnerabilityView {
    let vulnerability_count = dependency.vulnerability_count;
    let vulnerabilities = dependency
        .vulnerabilities
        .into_iter()
        .take(3)
        .map(|vulnerability| package_vulnerability_view(vulnerability, "not listed"))
        .collect::<Vec<_>>();
    let hidden_vulnerability_count = vulnerability_count.saturating_sub(vulnerabilities.len());
    DependencyVulnerabilityView {
        requirement: dependency.requirement,
        package_name: dependency.package_name,
        version: dependency.version,
        vulnerability_count,
        highest_severity: dependency.highest_severity,
        vulnerabilities,
        hidden_vulnerability_count,
        scan_error: dependency.scan_error,
    }
}

fn package_vulnerability_view(
    vulnerability: pyregistry_application::PackageVulnerability,
    empty_fixed_versions_label: &str,
) -> PackageVulnerabilityView {
    PackageVulnerabilityView {
        id: vulnerability.id,
        summary: vulnerability.summary,
        severity: vulnerability.severity,
        fixed_versions: if vulnerability.fixed_versions.is_empty() {
            empty_fixed_versions_label.into()
        } else {
            vulnerability.fixed_versions.join(", ")
        },
        primary_reference: vulnerability.references.into_iter().next(),
    }
}

fn attachment_content_disposition(filename: &str) -> String {
    let safe_filename = filename
        .chars()
        .map(|ch| match ch {
            '"' | '\\' => '_',
            ch if ch.is_ascii_graphic() || ch == ' ' => ch,
            _ => '_',
        })
        .collect::<String>();
    format!("attachment; filename=\"{safe_filename}\"")
}

fn registry_base_url(headers: &HeaderMap) -> String {
    let host = forwarded_value(headers, "x-forwarded-host")
        .or_else(|| forwarded_value(headers, header::HOST.as_str()))
        .unwrap_or("<registry-host>");
    let scheme =
        forwarded_value(headers, "x-forwarded-proto").unwrap_or_else(|| default_scheme_for(host));
    format!("{scheme}://{host}")
}

fn install_command(installer: &str, index_url: &str, project_name: &str) -> String {
    format!(
        "export PYREGISTRY_TOKEN=<token>\n{} --index-url \"{}\" {}",
        installer,
        authenticated_index_url(index_url),
        project_name
    )
}

fn authenticated_index_url(index_url: &str) -> String {
    if let Some((scheme, rest)) = index_url.split_once("://") {
        return format!("{scheme}://__token__:${{PYREGISTRY_TOKEN}}@{rest}");
    }

    format!("__token__:${{PYREGISTRY_TOKEN}}@{index_url}")
}

fn default_scheme_for(host: &str) -> &'static str {
    let host = host.to_ascii_lowercase();
    if host.starts_with("localhost")
        || host.starts_with("127.")
        || host.starts_with("[::1]")
        || host.starts_with("::1")
    {
        "http"
    } else {
        "https"
    }
}

fn format_wheel_audit_report_text(report: &WheelAuditReport) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "Wheel audit: {}", report.wheel_filename);
    let _ = writeln!(out, "Project: {}", report.project_name);
    let _ = writeln!(out, "Scanned files: {}", report.scanned_file_count);
    format_source_security_scan_summary(&mut out, report);
    format_virus_scan_summary(&mut out, report);

    if report.findings.is_empty() {
        let _ = writeln!(out);
        let _ = write!(
            out,
            "No suspicious heuristic signals, FoxGuard findings, or YARA virus signatures were detected."
        );
        return out;
    }

    for kind in [
        WheelAuditFindingKind::UnexpectedExecutable,
        WheelAuditFindingKind::NetworkString,
        WheelAuditFindingKind::PostInstallClue,
        WheelAuditFindingKind::PythonAstSuspiciousBehavior,
        WheelAuditFindingKind::SuspiciousDependency,
        WheelAuditFindingKind::SourceSecurityFinding,
        WheelAuditFindingKind::VirusSignatureMatch,
    ] {
        let findings: Vec<_> = report
            .findings
            .iter()
            .filter(|finding| finding.kind == kind)
            .collect();
        if findings.is_empty() {
            continue;
        }

        let _ = writeln!(out);
        let _ = writeln!(out, "{} ({})", audit_heading(kind), findings.len());
        for finding in findings {
            format_wheel_finding(&mut out, finding);
        }
    }

    out
}

fn format_source_security_scan_summary(out: &mut String, report: &WheelAuditReport) {
    let _ = writeln!(
        out,
        "FoxGuard source scan: {}",
        if report.source_security_scan.enabled {
            "enabled"
        } else {
            "unavailable"
        }
    );
    let _ = writeln!(
        out,
        "FoxGuard files inspected: {}, findings: {}",
        report.source_security_scan.scanned_file_count, report.source_security_scan.finding_count
    );
    if let Some(error) = &report.source_security_scan.scan_error {
        let _ = writeln!(out, "FoxGuard scan warning: {error}");
    }
}

fn format_virus_scan_summary(out: &mut String, report: &WheelAuditReport) {
    let _ = writeln!(
        out,
        "YARA virus scan: {}",
        if report.virus_scan.enabled {
            "enabled"
        } else {
            "unavailable"
        }
    );
    let _ = writeln!(
        out,
        "YARA rules loaded: {} (skipped {})",
        report.virus_scan.signature_rule_count, report.virus_scan.skipped_rule_count
    );
    let _ = writeln!(
        out,
        "YARA files scanned: {}, signature matches: {}",
        report.virus_scan.scanned_file_count, report.virus_scan.match_count
    );
    if let Some(error) = &report.virus_scan.scan_error {
        let _ = writeln!(out, "YARA scan warning: {error}");
    }
}

fn format_wheel_finding(out: &mut String, finding: &WheelAuditFinding) {
    match &finding.path {
        Some(path) => {
            let _ = writeln!(out, "- {} [{}]", finding.summary, path);
        }
        None => {
            let _ = writeln!(out, "- {}", finding.summary);
        }
    }

    for evidence in &finding.evidence {
        let _ = writeln!(out, "  evidence: {}", evidence);
    }
}

fn audit_heading(kind: WheelAuditFindingKind) -> &'static str {
    match kind {
        WheelAuditFindingKind::UnexpectedExecutable => "Unexpected executables or shell scripts",
        WheelAuditFindingKind::NetworkString => "Network-related strings inside binaries",
        WheelAuditFindingKind::PostInstallClue => "Post-install behavior clues",
        WheelAuditFindingKind::PythonAstSuspiciousBehavior => "Python AST suspicious behavior",
        WheelAuditFindingKind::SuspiciousDependency => "Suspicious dependencies in METADATA",
        WheelAuditFindingKind::SourceSecurityFinding => "FoxGuard source security findings",
        WheelAuditFindingKind::VirusSignatureMatch => "YARA virus signature matches",
    }
}

fn forwarded_value<'a>(headers: &'a HeaderMap, key: &str) -> Option<&'a str> {
    headers
        .get(key)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

#[cfg(test)]
mod tests {
    use super::{
        artifact_security_view, attachment_content_disposition, audit_heading,
        authenticated_index_url, default_scheme_for, format_wheel_audit_report_text,
        forwarded_value, package_detail_view, parse_issue_token_form, parse_optional_ttl_hours,
        registry_base_url,
    };
    use crate::models::PackageDetailTemplate;
    use askama::Template;
    use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
    use pyregistry_application::{
        ArtifactSecurityDetails, DependencyVulnerabilityDetails, PackageArtifactDetails,
        PackageDetails, PackageReleaseDetails, PackageSecuritySummary, PackageVulnerability,
        WheelAuditFinding, WheelAuditFindingKind, WheelAuditReport, WheelSourceSecurityScanSummary,
        WheelVirusScanSummary,
    };

    #[test]
    fn blank_ttl_hours_becomes_none() {
        assert_eq!(parse_optional_ttl_hours(None).expect("ttl"), None);
        assert_eq!(parse_optional_ttl_hours(Some("")).expect("ttl"), None);
        assert_eq!(parse_optional_ttl_hours(Some("   ")).expect("ttl"), None);
    }

    #[test]
    fn numeric_ttl_hours_parses() {
        assert_eq!(parse_optional_ttl_hours(Some("24")).expect("ttl"), Some(24));
    }

    #[test]
    fn invalid_ttl_hours_returns_bad_request() {
        let error = parse_optional_ttl_hours(Some("tomorrow")).expect_err("invalid ttl");

        assert_eq!(error.status, StatusCode::BAD_REQUEST);
        assert!(error.message.contains("TTL hours"));
    }

    #[test]
    fn parses_issue_token_form_with_repeated_scopes_and_blank_ttl() {
        let form = parse_issue_token_form(
            b"label=CI+token&ttl_hours=&scopes=read&ignored=value&scopes=publish&scopes=admin",
        )
        .expect("form");

        assert_eq!(form.label, "CI token");
        assert_eq!(form.ttl_hours.as_deref(), Some(""));
        assert_eq!(form.scopes, vec!["read", "publish", "admin"]);
    }

    #[test]
    fn issue_token_form_requires_non_empty_label() {
        let error = match parse_issue_token_form(b"label=++&scopes=read") {
            Ok(_) => panic!("missing label should fail"),
            Err(error) => error,
        };

        assert_eq!(error.status, StatusCode::BAD_REQUEST);
        assert!(error.message.contains("Token label"));
    }

    #[test]
    fn install_commands_export_token_before_referencing_it() {
        let details = PackageDetails {
            tenant_slug: "acme".into(),
            project_name: "rsloop".into(),
            normalized_name: "rsloop".into(),
            summary: String::new(),
            description: String::new(),
            source: "Local".into(),
            security: PackageSecuritySummary::default(),
            releases: Vec::new(),
            trusted_publishers: Vec::new(),
        };

        let view = package_detail_view(details, "http://127.0.0.1:3000");

        assert_eq!(view.index_url, "http://127.0.0.1:3000/t/acme/simple/");
        assert!(
            view.uv_install_command
                .starts_with("export PYREGISTRY_TOKEN=<token>\n")
        );
        assert!(
            view.uv_install_command
                .contains("http://__token__:${PYREGISTRY_TOKEN}@127.0.0.1:3000/t/acme/simple/")
        );
        assert!(
            !view
                .uv_install_command
                .starts_with("PYREGISTRY_TOKEN=<token> uv")
        );
    }

    #[test]
    fn package_detail_template_collapses_install_block_by_default() {
        let details = PackageDetails {
            tenant_slug: "acme".into(),
            project_name: "rsloop".into(),
            normalized_name: "rsloop".into(),
            summary: String::new(),
            description: String::new(),
            source: "Local".into(),
            security: PackageSecuritySummary::default(),
            releases: Vec::new(),
            trusted_publishers: Vec::new(),
        };

        let rendered = PackageDetailTemplate {
            details: package_detail_view(details, "http://127.0.0.1:3000"),
        }
        .render()
        .expect("render package detail");

        assert!(rendered.contains("<details class=\"install-panel\">"));
        assert!(!rendered.contains("<details class=\"install-panel\" open>"));
        assert!(rendered.contains("Index URL, pip, and uv commands"));
    }

    #[test]
    fn package_detail_template_labels_windows_gnu_pysentry_as_unavailable() {
        let unavailable = concat!(
            "1.0.0: PySentry vulnerability lookup is unavailable on Windows GNU targets; ",
            "1.0.1: PySentry vulnerability lookup is unavailable on Windows GNU targets"
        );
        let details = PackageDetails {
            tenant_slug: "acme".into(),
            project_name: "rsloop".into(),
            normalized_name: "rsloop".into(),
            summary: String::new(),
            description: String::new(),
            source: "Local".into(),
            security: PackageSecuritySummary {
                scan_error: Some(unavailable.into()),
                ..PackageSecuritySummary::default()
            },
            releases: vec![PackageReleaseDetails {
                version: "1.0.0".into(),
                yanked_reason: None,
                artifacts: vec![PackageArtifactDetails {
                    filename: "rsloop-1.0.0-py3-none-any.whl".into(),
                    version: "1.0.0".into(),
                    size_bytes: 42,
                    sha256: "abc123".into(),
                    object_key: "objects/rsloop.whl".into(),
                    yanked_reason: None,
                    security: ArtifactSecurityDetails::failed(
                        "PySentry vulnerability lookup is unavailable on Windows GNU targets",
                    ),
                }],
            }],
            trusted_publishers: Vec::new(),
        };

        let rendered = PackageDetailTemplate {
            details: package_detail_view(details, "http://127.0.0.1:3000"),
        }
        .render()
        .expect("render package detail");

        assert!(rendered.contains("PySentry scan unavailable on this server"));
        assert!(
            rendered
                .contains("PySentry vulnerability lookup is unavailable on Windows GNU targets")
        );
        assert!(rendered.contains("No release files were checked"));
        assert!(!rendered.contains("1.0.0:"));
        assert!(!rendered.contains("1.0.1:"));
        assert!(!rendered.contains("external dependency failure"));
        assert!(!rendered.contains("PySentry scan did not complete for every release file"));
        assert!(
            !rendered
                .contains("PySentry found no known vulnerabilities in 0 scanned release files")
        );
    }

    #[test]
    fn package_detail_template_lists_vulnerable_dependency_findings_in_modal() {
        let dependency = DependencyVulnerabilityDetails {
            requirement: "urllib3==1.24.1".into(),
            package_name: "urllib3".into(),
            version: "1.24.1".into(),
            vulnerability_count: 1,
            highest_severity: Some("HIGH".into()),
            vulnerabilities: vec![vulnerability(
                "GHSA-dep",
                "HIGH",
                vec!["1.26.5"],
                vec!["https://example.test/dep"],
            )],
            scan_error: None,
        };
        let details = PackageDetails {
            tenant_slug: "acme".into(),
            project_name: "rsloop".into(),
            normalized_name: "rsloop".into(),
            summary: String::new(),
            description: String::new(),
            source: "Local".into(),
            security: PackageSecuritySummary {
                scanned_dependency_count: 1,
                vulnerable_dependency_count: 1,
                dependency_vulnerability_count: 1,
                ..PackageSecuritySummary::default()
            },
            releases: vec![PackageReleaseDetails {
                version: "1.0.0".into(),
                yanked_reason: None,
                artifacts: vec![PackageArtifactDetails {
                    filename: "rsloop-1.0.0-py3-none-any.whl".into(),
                    version: "1.0.0".into(),
                    size_bytes: 42,
                    sha256: "abc123".into(),
                    object_key: "objects/rsloop.whl".into(),
                    yanked_reason: None,
                    security: ArtifactSecurityDetails::scanned(Vec::new())
                        .with_dependencies(vec![dependency], None),
                }],
            }],
            trusted_publishers: Vec::new(),
        };

        let rendered = PackageDetailTemplate {
            details: package_detail_view(details, "http://127.0.0.1:3000"),
        }
        .render()
        .expect("render package detail");

        assert!(rendered.contains("Vulnerable requirements: <strong>1</strong>"));
        assert!(rendered.contains("View dependency findings"));
        assert!(rendered.contains("<dialog id=\"dependency-findings-modal\">"));
        assert!(rendered.contains("Vulnerable dependency findings"));
        assert!(rendered.contains("<strong>urllib3==1.24.1</strong>"));
        assert!(rendered.contains("urllib3==1.24.1"));
        assert!(rendered.contains("Found in rsloop-1.0.0-py3-none-any.whl"));
        assert!(rendered.contains("<strong>GHSA-dep</strong> HIGH"));
        assert!(rendered.contains("Fixed versions: 1.26.5"));
        assert!(rendered.contains("document.querySelectorAll(\".dependency-findings-button\")"));
    }

    #[test]
    fn package_detail_view_exposes_admin_download_url_for_release_files() {
        let details = PackageDetails {
            tenant_slug: "acme".into(),
            project_name: "rsloop".into(),
            normalized_name: "rsloop".into(),
            summary: String::new(),
            description: String::new(),
            source: "Local".into(),
            security: PackageSecuritySummary::default(),
            releases: vec![PackageReleaseDetails {
                version: "0.1.14".into(),
                yanked_reason: None,
                artifacts: vec![PackageArtifactDetails {
                    filename: "rsloop-0.1.14-py3-none-any.whl".into(),
                    version: "0.1.14".into(),
                    size_bytes: 42,
                    sha256: "abc123".into(),
                    object_key: "objects/rsloop.whl".into(),
                    yanked_reason: None,
                    security: ArtifactSecurityDetails::pending(),
                }],
            }],
            trusted_publishers: Vec::new(),
        };

        let view = package_detail_view(details, "http://127.0.0.1:3000");
        let artifact = &view.releases[0].artifacts[0];

        assert_eq!(
            artifact.download_url,
            "/admin/t/acme/packages/rsloop/releases/0.1.14/artifacts/rsloop-0.1.14-py3-none-any.whl/download"
        );
        assert_eq!(artifact.size_human, "42.0 B");
    }

    #[test]
    fn package_detail_template_hides_active_release_controls_in_modal() {
        let details = PackageDetails {
            tenant_slug: "acme".into(),
            project_name: "rsloop".into(),
            normalized_name: "rsloop".into(),
            summary: String::new(),
            description: String::new(),
            source: "Local".into(),
            security: PackageSecuritySummary::default(),
            releases: vec![PackageReleaseDetails {
                version: "0.1.14".into(),
                yanked_reason: None,
                artifacts: vec![PackageArtifactDetails {
                    filename: "rsloop-0.1.14-py3-none-any.whl".into(),
                    version: "0.1.14".into(),
                    size_bytes: 42,
                    sha256: "abc123".into(),
                    object_key: "objects/rsloop.whl".into(),
                    yanked_reason: None,
                    security: ArtifactSecurityDetails::pending(),
                }],
            }],
            trusted_publishers: Vec::new(),
        };

        let rendered = PackageDetailTemplate {
            details: package_detail_view(details, "http://127.0.0.1:3000"),
        }
        .render()
        .expect("render package detail");

        let manage_position = rendered.find("Manage release").expect("manage release");
        let modal_position = rendered
            .find("release-governance-modal")
            .expect("release modal");
        let active_position = rendered
            .find("Release is active")
            .expect("active release controls");

        assert!(manage_position < modal_position);
        assert!(modal_position < active_position);
        assert!(rendered.contains("document.querySelectorAll(\".manage-release-button\")"));
    }

    #[test]
    fn package_detail_template_hides_file_controls_in_modal() {
        let details = PackageDetails {
            tenant_slug: "acme".into(),
            project_name: "rsloop".into(),
            normalized_name: "rsloop".into(),
            summary: String::new(),
            description: String::new(),
            source: "Local".into(),
            security: PackageSecuritySummary::default(),
            releases: vec![PackageReleaseDetails {
                version: "0.1.14".into(),
                yanked_reason: None,
                artifacts: vec![PackageArtifactDetails {
                    filename: "rsloop-0.1.14-py3-none-any.whl".into(),
                    version: "0.1.14".into(),
                    size_bytes: 42,
                    sha256: "abc123".into(),
                    object_key: "objects/rsloop.whl".into(),
                    yanked_reason: None,
                    security: ArtifactSecurityDetails::pending(),
                }],
            }],
            trusted_publishers: Vec::new(),
        };

        let rendered = PackageDetailTemplate {
            details: package_detail_view(details, "http://127.0.0.1:3000"),
        }
        .render()
        .expect("render package detail");

        let manage_position = rendered.find("Manage file").expect("manage file");
        let modal_position = rendered.find("file-governance-modal").expect("file modal");
        let active_position = rendered
            .find("File is active")
            .expect("active file controls");

        assert!(manage_position < modal_position);
        assert!(modal_position < active_position);
        assert!(rendered.contains("document.querySelectorAll(\".manage-file-button\")"));
    }

    #[test]
    fn package_detail_template_shows_stateful_yank_controls() {
        let details = PackageDetails {
            tenant_slug: "acme".into(),
            project_name: "rsloop".into(),
            normalized_name: "rsloop".into(),
            summary: String::new(),
            description: String::new(),
            source: "Local".into(),
            security: PackageSecuritySummary::default(),
            releases: vec![PackageReleaseDetails {
                version: "0.1.14".into(),
                yanked_reason: Some("broken metadata".into()),
                artifacts: vec![PackageArtifactDetails {
                    filename: "rsloop-0.1.14-py3-none-any.whl".into(),
                    version: "0.1.14".into(),
                    size_bytes: 42,
                    sha256: "abc123".into(),
                    object_key: "objects/rsloop.whl".into(),
                    yanked_reason: Some("bad wheel tag".into()),
                    security: ArtifactSecurityDetails::pending(),
                }],
            }],
            trusted_publishers: Vec::new(),
        };

        let rendered = PackageDetailTemplate {
            details: package_detail_view(details, "http://127.0.0.1:3000"),
        }
        .render()
        .expect("render package detail");

        assert!(rendered.contains("Release is yanked"));
        assert!(rendered.contains("Unyank release"));
        assert!(rendered.contains("File is yanked"));
        assert!(rendered.contains("Unyank file"));
        assert!(!rendered.contains(">Yank release</button>"));
        assert!(!rendered.contains(">Yank file</button>"));
    }

    #[test]
    fn artifact_security_view_formats_visible_and_hidden_vulnerabilities() {
        let security = ArtifactSecurityDetails::scanned(vec![
            vulnerability("GHSA-1", "LOW", vec![], vec![]),
            vulnerability(
                "GHSA-2",
                "MEDIUM",
                vec!["1.2.0"],
                vec!["https://example.test/2"],
            ),
            vulnerability("GHSA-3", "HIGH", vec!["2.0.0", "2.0.1"], vec![]),
            vulnerability("GHSA-4", "CRITICAL", vec![], vec!["https://example.test/4"]),
        ])
        .with_dependencies(
            vec![DependencyVulnerabilityDetails {
                requirement: "urllib3==1.24.1".into(),
                package_name: "urllib3".into(),
                version: "1.24.1".into(),
                vulnerability_count: 1,
                highest_severity: Some("HIGH".into()),
                vulnerabilities: vec![vulnerability(
                    "GHSA-dep",
                    "HIGH",
                    vec!["1.26.5"],
                    vec!["https://example.test/dep"],
                )],
                scan_error: None,
            }],
            None,
        );

        let view = artifact_security_view(security);

        assert!(view.scanned);
        assert_eq!(view.vulnerability_count, 4);
        assert_eq!(view.hidden_vulnerability_count, 1);
        assert_eq!(view.vulnerabilities.len(), 3);
        assert_eq!(
            view.vulnerabilities[0].fixed_versions,
            "no fixed version listed"
        );
        assert_eq!(view.vulnerabilities[1].fixed_versions, "1.2.0");
        assert_eq!(
            view.vulnerabilities[1].primary_reference.as_deref(),
            Some("https://example.test/2")
        );
        assert_eq!(view.vulnerabilities[2].fixed_versions, "2.0.0, 2.0.1");
        assert_eq!(view.dependency_count, 1);
        assert_eq!(view.vulnerable_dependency_count, 1);
        assert_eq!(view.dependencies[0].package_name, "urllib3");
        assert_eq!(view.dependencies[0].vulnerabilities[0].id, "GHSA-dep");
    }

    #[test]
    fn attachment_content_disposition_sanitizes_unsafe_filename_chars() {
        assert_eq!(
            attachment_content_disposition("safe-1.0.0.whl"),
            "attachment; filename=\"safe-1.0.0.whl\""
        );
        assert_eq!(
            attachment_content_disposition("bad\"name\\file.whl"),
            "attachment; filename=\"bad_name_file.whl\""
        );
    }

    #[test]
    fn authenticated_index_url_preserves_configured_scheme() {
        assert_eq!(
            authenticated_index_url("http://127.0.0.1:3000/t/acme/simple/"),
            "http://__token__:${PYREGISTRY_TOKEN}@127.0.0.1:3000/t/acme/simple/"
        );
        assert_eq!(
            authenticated_index_url("https://registry.example/t/acme/simple/"),
            "https://__token__:${PYREGISTRY_TOKEN}@registry.example/t/acme/simple/"
        );
        assert_eq!(
            authenticated_index_url("registry.example/t/acme/simple/"),
            "__token__:${PYREGISTRY_TOKEN}@registry.example/t/acme/simple/"
        );
    }

    #[test]
    fn default_scheme_uses_http_for_loopback_hosts() {
        assert_eq!(default_scheme_for("127.0.0.1:3000"), "http");
        assert_eq!(default_scheme_for("localhost:3000"), "http");
        assert_eq!(default_scheme_for("[::1]:3000"), "http");
        assert_eq!(default_scheme_for("registry.example"), "https");
    }

    #[test]
    fn registry_base_url_prefers_forwarded_headers_and_ignores_empty_values() {
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, HeaderValue::from_static("127.0.0.1:3000"));
        assert_eq!(registry_base_url(&headers), "http://127.0.0.1:3000");

        headers.insert(
            "x-forwarded-host",
            HeaderValue::from_static("registry.example, proxy.local"),
        );
        headers.insert("x-forwarded-proto", HeaderValue::from_static("https"));
        assert_eq!(registry_base_url(&headers), "https://registry.example");

        headers.insert("x-forwarded-host", HeaderValue::from_static("   "));
        assert_eq!(
            forwarded_value(&headers, "x-forwarded-host"),
            None,
            "blank forwarded values should be ignored"
        );
    }

    #[test]
    fn formats_wheel_audit_reports_for_clean_and_finding_cases() {
        let clean = WheelAuditReport {
            project_name: "demo".into(),
            wheel_filename: "demo-1.0.0-py3-none-any.whl".into(),
            scanned_file_count: 3,
            source_security_scan: WheelSourceSecurityScanSummary::failed("foxguard unavailable"),
            virus_scan: WheelVirusScanSummary::failed("yara unavailable"),
            findings: Vec::new(),
        };

        let clean_text = format_wheel_audit_report_text(&clean);
        assert!(clean_text.contains("FoxGuard source scan: unavailable"));
        assert!(clean_text.contains("FoxGuard scan warning: foxguard unavailable"));
        assert!(clean_text.contains("YARA virus scan: unavailable"));
        assert!(clean_text.contains("YARA scan warning: yara unavailable"));
        assert!(clean_text.contains("No suspicious heuristic signals"));

        let report = WheelAuditReport {
            project_name: "demo".into(),
            wheel_filename: "demo-1.0.0-py3-none-any.whl".into(),
            scanned_file_count: 4,
            source_security_scan: WheelSourceSecurityScanSummary {
                enabled: true,
                scanned_file_count: 4,
                finding_count: 1,
                scan_error: None,
            },
            virus_scan: WheelVirusScanSummary {
                enabled: true,
                scanned_file_count: 4,
                signature_rule_count: 12,
                skipped_rule_count: 1,
                match_count: 1,
                scan_error: None,
            },
            findings: vec![
                finding(
                    WheelAuditFindingKind::UnexpectedExecutable,
                    Some("bin/tool"),
                    "exec",
                ),
                finding(WheelAuditFindingKind::NetworkString, None, "network"),
                finding(
                    WheelAuditFindingKind::PostInstallClue,
                    Some("setup.py"),
                    "post install",
                ),
                finding(
                    WheelAuditFindingKind::PythonAstSuspiciousBehavior,
                    Some("pkg/__init__.py"),
                    "ast",
                ),
                finding(
                    WheelAuditFindingKind::SuspiciousDependency,
                    Some("METADATA"),
                    "dep",
                ),
                finding(
                    WheelAuditFindingKind::SourceSecurityFinding,
                    Some("pkg/mod.py"),
                    "source",
                ),
                finding(
                    WheelAuditFindingKind::VirusSignatureMatch,
                    Some("pkg/mod.py"),
                    "virus",
                ),
            ],
        };

        let text = format_wheel_audit_report_text(&report);
        assert!(text.contains(audit_heading(WheelAuditFindingKind::UnexpectedExecutable)));
        assert!(text.contains(audit_heading(WheelAuditFindingKind::VirusSignatureMatch)));
        assert!(text.contains("- network"));
        assert!(text.contains("- exec [bin/tool]"));
        assert!(text.contains("evidence: fixture"));
    }

    fn vulnerability(
        id: &str,
        severity: &str,
        fixed_versions: Vec<&str>,
        references: Vec<&str>,
    ) -> PackageVulnerability {
        PackageVulnerability {
            id: id.into(),
            summary: format!("{id} summary"),
            severity: severity.into(),
            fixed_versions: fixed_versions.into_iter().map(str::to_string).collect(),
            references: references.into_iter().map(str::to_string).collect(),
            source: Some("test".into()),
            cvss_score: None,
        }
    }

    fn finding(
        kind: WheelAuditFindingKind,
        path: Option<&str>,
        summary: &str,
    ) -> WheelAuditFinding {
        WheelAuditFinding {
            kind,
            path: path.map(str::to_string),
            summary: summary.into(),
            evidence: vec!["fixture".into()],
        }
    }
}
