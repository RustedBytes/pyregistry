use anyhow::Context;
use async_trait::async_trait;
use log::{debug, error, info, warn};
use pyregistry_application::{
    ApplicationError, CancellationSignal, MirrorRefreshReport, PyregistryApp,
};
use pyregistry_infrastructure::{Settings, build_application, seed_application};
use pyregistry_web::{
    AppState, NetworkSourceConfig as WebNetworkSourceConfig, NetworkSourcePolicy,
    RateLimitConfig as WebRateLimitConfig, RateLimiter, router,
};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tower_http::trace::TraceLayer;

const FORCED_HTTP_SHUTDOWN_GRACE: Duration = Duration::from_secs(5);
const MIRROR_UPDATER_SHUTDOWN_GRACE: Duration = Duration::from_secs(5);
pub(crate) async fn serve(
    settings: Settings,
    config_source: String,
    allow_insecure: bool,
) -> anyhow::Result<()> {
    log_startup_settings(&settings, &config_source);

    info!("building application services");
    let app = build_seeded_application(&settings).await?;
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let mirror_updater = spawn_mirror_updater(app.clone(), &settings, shutdown_rx.clone());
    let forced_shutdown_rx = shutdown_rx.clone();

    let listener = bind_listener(&settings).await?;
    let state = build_web_state(app, &settings, allow_insecure);
    log_http_policy(&state);
    let router = router(state).layer(TraceLayer::new_for_http());

    info!("pyregistry listening on http://{}", settings.bind_address);
    let serve_result =
        run_http_server(listener, router, shutdown_tx.clone(), forced_shutdown_rx).await;

    signal_shutdown(&shutdown_tx, "HTTP server finished");
    wait_for_mirror_updater(mirror_updater).await;

    if let Err(error) = serve_result {
        error!("axum server terminated with an error: {error}");
        return Err(error).context("axum server failed");
    }

    info!("pyregistry server shutdown complete");
    Ok(())
}

fn log_startup_settings(settings: &Settings, config_source: &str) {
    info!("starting pyregistry server");
    info!("loading settings from {config_source}");
    info!("runtime settings: {}", settings.log_safe_summary());
    if let Ok(override_filter) = std::env::var("RUST_LOG") {
        info!("RUST_LOG override detected: {override_filter}");
    }
    debug!(
        "configured OIDC issuers: {:?}",
        settings
            .oidc_issuers
            .iter()
            .map(|issuer| (
                &issuer.provider,
                issuer.issuer.as_str(),
                issuer.audience.as_str()
            ))
            .collect::<Vec<_>>()
    );
}

async fn build_seeded_application(settings: &Settings) -> anyhow::Result<Arc<PyregistryApp>> {
    let app = build_application(&settings)
        .await
        .context("failed to build application services")?;
    info!("seeding bootstrap data");
    seed_application(&app, &settings)
        .await
        .context("failed to seed application")?;
    info!("bootstrap data ready");
    Ok(app)
}

async fn bind_listener(settings: &Settings) -> anyhow::Result<TcpListener> {
    info!("binding TCP listener on {}", settings.bind_address);
    TcpListener::bind(&settings.bind_address)
        .await
        .with_context(|| format!("failed to bind {}", settings.bind_address))
}

fn build_web_state(app: Arc<PyregistryApp>, settings: &Settings, allow_insecure: bool) -> AppState {
    let allow_insecure_admin_cookies = allow_insecure || settings.web_ui.allow_insecure;
    let secure_admin_cookies =
        !allow_insecure_admin_cookies && bind_address_is_public(&settings.bind_address);
    if allow_insecure_admin_cookies {
        warn!(
            "insecure admin cookies are enabled; admin session cookies will be sent over plain HTTP. Use only on trusted private networks."
        );
    }

    AppState::new(
        app,
        RateLimiter::new(WebRateLimitConfig {
            enabled: settings.rate_limit.enabled,
            requests_per_minute: settings.rate_limit.requests_per_minute,
            burst: settings.rate_limit.burst,
            max_tracked_clients: settings.rate_limit.max_tracked_clients,
            trust_proxy_headers: settings.rate_limit.trust_proxy_headers,
        }),
        NetworkSourcePolicy::new(WebNetworkSourceConfig {
            web_ui_allowed_cidrs: settings.network_source.web_ui_allowed_cidrs.clone(),
            api_allowed_cidrs: settings.network_source.api_allowed_cidrs.clone(),
            trust_proxy_headers: settings.network_source.trust_proxy_headers,
        }),
        settings.web_ui.show_index_stats,
        enabled_build_features(),
        secure_admin_cookies,
        None,
    )
}

fn log_http_policy(state: &AppState) {
    info!(
        "HTTP API rate limiting: {}",
        state.rate_limiter.log_safe_summary()
    );
    info!(
        "HTTP network source access: {}",
        state.network_source.log_safe_summary()
    );
}

async fn run_http_server(
    listener: TcpListener,
    router: RouterWithTrace,
    shutdown_tx: watch::Sender<bool>,
    forced_shutdown_rx: watch::Receiver<bool>,
) -> std::io::Result<()> {
    let server = axum::serve(
        listener,
        router.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal(shutdown_tx.clone()));

    tokio::select! {
        result = server => result,
        () = force_http_shutdown_after_signal(forced_shutdown_rx, FORCED_HTTP_SHUTDOWN_GRACE) => {
            warn!(
                "forcing HTTP shutdown after {:.1}s grace period",
                FORCED_HTTP_SHUTDOWN_GRACE.as_secs_f64()
            );
            Ok(())
        }
    }
}

type RouterWithTrace = axum::Router;

fn signal_shutdown(shutdown_tx: &watch::Sender<bool>, reason: &str) {
    if shutdown_tx.send(true).is_err() {
        debug!("shutdown signal dropped because no receivers remain ({reason})");
    }
}

fn bind_address_is_public(bind_address: &str) -> bool {
    let host = bind_address
        .rsplit_once(':')
        .map_or(bind_address, |(host, _)| host)
        .trim()
        .trim_matches(['[', ']']);
    !matches!(host, "127.0.0.1" | "::1" | "localhost")
}

pub(crate) fn enabled_build_features() -> Vec<String> {
    [
        ("minimal-local", cfg!(feature = "minimal-local")),
        ("sqlite", cfg!(feature = "sqlite")),
        ("postgres", cfg!(feature = "postgres")),
        ("sqlserver", cfg!(feature = "sqlserver")),
        ("opendal-fs", cfg!(feature = "opendal-fs")),
        ("s3", cfg!(feature = "s3")),
        ("security-default", cfg!(feature = "security-default")),
        ("security-full", cfg!(feature = "security-full")),
        ("source-security", cfg!(feature = "source-security")),
        ("file-type-ml", cfg!(feature = "file-type-ml")),
        ("vulnerability-db", cfg!(feature = "vulnerability-db")),
        ("virus-yara", cfg!(feature = "virus-yara")),
        ("python-ast-audit", cfg!(feature = "python-ast-audit")),
    ]
    .into_iter()
    .filter_map(|(name, enabled)| enabled.then_some(name.to_string()))
    .collect()
}

pub(crate) fn spawn_mirror_updater(
    app: Arc<PyregistryApp>,
    settings: &Settings,
    mut shutdown: watch::Receiver<bool>,
) -> Option<JoinHandle<()>> {
    if !settings.pypi.mirror_update_enabled {
        info!("background mirrored package updater is disabled");
        return None;
    }

    let interval = Duration::from_secs(settings.pypi.mirror_update_interval_seconds);
    let run_on_startup = settings.pypi.mirror_update_on_startup;
    info!(
        "starting background mirrored package updater: interval_seconds={}, run_on_startup={}",
        settings.pypi.mirror_update_interval_seconds, run_on_startup
    );

    Some(tokio::spawn(async move {
        if run_on_startup {
            run_mirror_update_cycle(&app, &shutdown).await;
            if *shutdown.borrow() {
                info!(
                    "background mirrored package updater stopping after startup cycle cancellation"
                );
                return;
            }
        }

        loop {
            tokio::select! {
                changed = shutdown.changed() => {
                    match changed {
                        Ok(()) if *shutdown.borrow() => {
                            info!("background mirrored package updater received shutdown signal");
                            break;
                        }
                        Ok(()) => {}
                        Err(_) => {
                            info!("background mirrored package updater shutdown channel closed");
                            break;
                        }
                    }
                }
                _ = tokio::time::sleep(interval) => {
                    if *shutdown.borrow() {
                        info!("background mirrored package updater stopping before next cycle");
                        break;
                    }
                    run_mirror_update_cycle(&app, &shutdown).await;
                }
            }
        }

        info!("background mirrored package updater stopped");
    }))
}

pub(crate) async fn wait_for_mirror_updater(handle: Option<JoinHandle<()>>) {
    if let Some(mut handle) = handle {
        tokio::select! {
            result = &mut handle => {
                if let Err(error) = result {
                    error!("background mirrored package updater task failed: {error}");
                }
            }
            _ = tokio::time::sleep(MIRROR_UPDATER_SHUTDOWN_GRACE) => {
                warn!(
                    "background mirrored package updater did not stop within {:.1}s; aborting task",
                    MIRROR_UPDATER_SHUTDOWN_GRACE.as_secs_f64()
                );
                handle.abort();
                if let Err(error) = handle.await
                    && !error.is_cancelled()
                {
                    error!("background mirrored package updater task failed during abort: {error}");
                }
            }
        }
    }
}

async fn run_mirror_update_cycle(app: &Arc<PyregistryApp>, shutdown: &watch::Receiver<bool>) {
    let started = Instant::now();
    info!("background mirrored package updater cycle started");
    let cancellation = WatchCancellation::new(shutdown.clone());
    match app
        .refresh_mirrored_projects_with_cancellation(&cancellation)
        .await
    {
        Ok(report) => log_mirror_refresh_report(&report, started.elapsed()),
        Err(ApplicationError::Cancelled(reason)) => {
            info!("background mirrored package updater cycle cancelled: {reason}")
        }
        Err(error) => warn!("background mirrored package updater cycle failed: {error}"),
    }
}

#[derive(Clone)]
pub(crate) struct WatchCancellation {
    shutdown: watch::Receiver<bool>,
}

impl WatchCancellation {
    pub(crate) fn new(shutdown: watch::Receiver<bool>) -> Self {
        Self { shutdown }
    }
}

#[async_trait]
impl CancellationSignal for WatchCancellation {
    fn is_cancelled(&self) -> bool {
        *self.shutdown.borrow()
    }

    async fn cancelled(&self) {
        let mut shutdown = self.shutdown.clone();
        if *shutdown.borrow() {
            return;
        }

        loop {
            if shutdown.changed().await.is_err() || *shutdown.borrow() {
                return;
            }
        }
    }
}

pub(crate) fn log_mirror_refresh_report(report: &MirrorRefreshReport, elapsed: Duration) {
    info!(
        "background mirrored package updater cycle finished in {:.2}s: tenants={}, mirrored_projects={}, refreshed={}, failed={}",
        elapsed.as_secs_f64(),
        report.tenant_count,
        report.mirrored_project_count,
        report.refreshed_project_count,
        report.failed_project_count
    );
    for failure in &report.failures {
        warn!(
            "background mirrored package updater failure: tenant=`{}` project=`{}` error={}",
            failure.tenant_slug, failure.project_name, failure.error
        );
    }
}

async fn shutdown_signal(shutdown_tx: watch::Sender<bool>) {
    let ctrl_c = async {
        match tokio::signal::ctrl_c().await {
            Ok(()) => "SIGINT",
            Err(error) => {
                error!("failed to listen for Ctrl+C/SIGINT: {error}");
                std::future::pending::<&'static str>().await
            }
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
                "SIGTERM"
            }
            Err(error) => {
                error!("failed to listen for SIGTERM: {error}");
                std::future::pending::<&'static str>().await
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<&'static str>();

    let received_signal = tokio::select! {
        signal = ctrl_c => signal,
        signal = terminate => signal,
    };
    info!("received {received_signal}; starting graceful HTTP shutdown");
    signal_shutdown(&shutdown_tx, received_signal);
}

pub(crate) async fn force_http_shutdown_after_signal(
    mut shutdown: watch::Receiver<bool>,
    grace_period: Duration,
) {
    if !*shutdown.borrow() {
        loop {
            if shutdown.changed().await.is_err() {
                return;
            }
            if *shutdown.borrow() {
                break;
            }
        }
    }

    tokio::time::sleep(grace_period).await;
}
