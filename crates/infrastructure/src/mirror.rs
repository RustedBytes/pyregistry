use async_trait::async_trait;
use log::{debug, info, warn};
use pyregistry_application::{
    ApplicationError, MirrorClient, MirroredArtifactSnapshot, MirroredProjectSnapshot,
};
use reqwest::StatusCode;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;
use tokio::fs;
use tokio::io::AsyncWriteExt;
use tokio::time::sleep;
use url::Url;

pub const DEFAULT_MIRROR_HTTP_TIMEOUT: Duration = Duration::from_secs(30);
pub const DEFAULT_MIRROR_METADATA_MAX_BYTES: u64 = 10 * 1024 * 1024;
pub const DEFAULT_MIRROR_ARTIFACT_MAX_BYTES: u64 = 100 * 1024 * 1024;

#[derive(Clone)]
pub struct PypiMirrorClient {
    client: reqwest::Client,
    base_url: Url,
    retry_policy: ArtifactDownloadRetryPolicy,
    limits: MirrorDownloadLimits,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MirrorDownloadLimits {
    http_timeout: Duration,
    metadata_max_bytes: u64,
    artifact_max_bytes: u64,
}

impl Default for MirrorDownloadLimits {
    fn default() -> Self {
        Self {
            http_timeout: DEFAULT_MIRROR_HTTP_TIMEOUT,
            metadata_max_bytes: DEFAULT_MIRROR_METADATA_MAX_BYTES,
            artifact_max_bytes: DEFAULT_MIRROR_ARTIFACT_MAX_BYTES,
        }
    }
}

impl MirrorDownloadLimits {
    #[must_use]
    pub fn new(http_timeout: Duration, metadata_max_bytes: u64, artifact_max_bytes: u64) -> Self {
        Self {
            http_timeout: http_timeout.max(Duration::from_millis(1)),
            metadata_max_bytes: metadata_max_bytes.max(1),
            artifact_max_bytes: artifact_max_bytes.max(1),
        }
    }

    #[must_use]
    pub fn http_timeout(self) -> Duration {
        self.http_timeout
    }

    #[must_use]
    pub fn metadata_max_bytes(self) -> u64 {
        self.metadata_max_bytes
    }

    #[must_use]
    pub fn artifact_max_bytes(self) -> u64 {
        self.artifact_max_bytes
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArtifactDownloadRetryPolicy {
    max_attempts: usize,
    initial_backoff: Duration,
}

impl Default for ArtifactDownloadRetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            initial_backoff: Duration::from_millis(250),
        }
    }
}

impl ArtifactDownloadRetryPolicy {
    #[must_use]
    pub fn new(max_attempts: usize, initial_backoff: Duration) -> Self {
        Self {
            max_attempts: max_attempts.max(1),
            initial_backoff,
        }
    }

    #[must_use]
    pub fn max_attempts(self) -> usize {
        self.max_attempts
    }

    #[must_use]
    pub fn initial_backoff(self) -> Duration {
        self.initial_backoff
    }

    #[must_use]
    fn delay_for_attempt(self, attempt: usize) -> Duration {
        let multiplier = 1_u32 << attempt.saturating_sub(1).min(16);
        self.initial_backoff.saturating_mul(multiplier)
    }
}

impl Default for PypiMirrorClient {
    fn default() -> Self {
        Self::new("https://pypi.org").expect("default PyPI URL is valid")
    }
}

impl PypiMirrorClient {
    pub fn new(base_url: &str) -> Result<Self, ApplicationError> {
        Self::with_retry_policy(base_url, ArtifactDownloadRetryPolicy::default())
    }

    pub fn with_retry_policy(
        base_url: &str,
        retry_policy: ArtifactDownloadRetryPolicy,
    ) -> Result<Self, ApplicationError> {
        Self::with_retry_policy_and_limits(base_url, retry_policy, MirrorDownloadLimits::default())
    }

    pub fn with_retry_policy_and_limits(
        base_url: &str,
        retry_policy: ArtifactDownloadRetryPolicy,
        limits: MirrorDownloadLimits,
    ) -> Result<Self, ApplicationError> {
        let normalized = base_url.trim().trim_end_matches('/');
        let base_url = Url::parse(normalized)
            .map_err(|error| ApplicationError::External(error.to_string()))?;
        let client = reqwest::Client::builder()
            .timeout(limits.http_timeout())
            .redirect(reqwest::redirect::Policy::limited(5))
            .build()
            .map_err(|error| ApplicationError::External(error.to_string()))?;
        Ok(Self {
            client,
            base_url,
            retry_policy,
            limits,
        })
    }

    fn project_metadata_url(&self, project_name: &str) -> Result<Url, ApplicationError> {
        self.base_url
            .join(&format!("/pypi/{project_name}/json"))
            .map_err(|error| ApplicationError::External(error.to_string()))
    }

    pub async fn download_project_artifact_by_filename(
        &self,
        project_name: &str,
        filename: &str,
        destination: &Path,
    ) -> Result<(), ApplicationError> {
        info!("resolving upstream artifact `{filename}` for project `{project_name}`");
        let project = self
            .fetch_project(project_name)
            .await?
            .ok_or_else(|| ApplicationError::NotFound(format!("project `{project_name}`")))?;
        let artifact =
            find_artifact_by_filename(&project.artifacts, filename).ok_or_else(|| {
                ApplicationError::NotFound(format!(
                    "artifact `{filename}` for project `{project_name}`"
                ))
            })?;

        self.stream_artifact_to_path(&artifact.download_url, artifact.size_bytes, destination)
            .await
    }

    async fn stream_artifact_to_path(
        &self,
        download_url: &str,
        expected_size_bytes: u64,
        destination: &Path,
    ) -> Result<(), ApplicationError> {
        info!(
            "streaming upstream artifact from `{download_url}` to {}",
            destination.display()
        );

        if let Some(parent) = destination
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            fs::create_dir_all(parent)
                .await
                .map_err(|error| ApplicationError::External(error.to_string()))?;
        }

        let temp_path = temp_download_path(destination);
        for attempt in 1..=self.retry_policy.max_attempts() {
            match self
                .stream_artifact_to_path_once(
                    download_url,
                    expected_size_bytes,
                    destination,
                    &temp_path,
                )
                .await
            {
                Ok(()) => return Ok(()),
                Err(error) if should_retry_download(&error, attempt, self.retry_policy) => {
                    let delay = self.retry_policy.delay_for_attempt(attempt);
                    warn!(
                        "artifact download attempt {}/{} failed for `{download_url}`: {}; retrying in {} ms",
                        attempt,
                        self.retry_policy.max_attempts(),
                        error.error,
                        delay.as_millis()
                    );
                    let _ = fs::remove_file(&temp_path).await;
                    sleep(delay).await;
                }
                Err(error) => {
                    let _ = fs::remove_file(&temp_path).await;
                    return Err(error.error);
                }
            }
        }

        Err(ApplicationError::External(format!(
            "artifact download retry loop exhausted for `{download_url}`"
        )))
    }

    async fn stream_artifact_to_path_once(
        &self,
        download_url: &str,
        expected_size_bytes: u64,
        destination: &Path,
        temp_path: &Path,
    ) -> Result<(), ArtifactDownloadError> {
        let mut response = self.get_artifact_response(download_url).await?;
        ensure_content_length_within_limit(
            response.content_length(),
            expected_size_bytes,
            self.limits.artifact_max_bytes(),
            download_url,
        )?;
        let mut file = fs::File::create(temp_path)
            .await
            .map_err(|error| ArtifactDownloadError::fatal(error.to_string()))?;
        let mut downloaded_bytes = 0_u64;

        loop {
            let chunk = response
                .chunk()
                .await
                .map_err(ArtifactDownloadError::from_reqwest)?;
            let Some(chunk) = chunk else {
                break;
            };

            downloaded_bytes = downloaded_bytes.saturating_add(chunk.len() as u64);
            if downloaded_bytes > self.limits.artifact_max_bytes()
                || (expected_size_bytes > 0 && downloaded_bytes > expected_size_bytes)
            {
                return Err(ArtifactDownloadError::fatal(format!(
                    "downloaded artifact `{download_url}` exceeded the allowed size"
                )));
            }
            file.write_all(&chunk)
                .await
                .map_err(|error| ArtifactDownloadError::fatal(error.to_string()))?;
            debug!(
                "downloaded chunk of {} byte(s) for {}, total={} byte(s)",
                chunk.len(),
                destination.display(),
                downloaded_bytes
            );
        }

        file.flush()
            .await
            .map_err(|error| ArtifactDownloadError::fatal(error.to_string()))?;
        drop(file);

        if expected_size_bytes > 0 && downloaded_bytes != expected_size_bytes {
            return Err(ArtifactDownloadError::retryable(format!(
                "downloaded size mismatch for {}: expected {} byte(s), got {} byte(s)",
                destination.display(),
                expected_size_bytes,
                downloaded_bytes
            )));
        }

        fs::rename(temp_path, destination)
            .await
            .map_err(|error| ArtifactDownloadError::fatal(error.to_string()))?;
        info!(
            "saved upstream artifact to {} ({} byte(s))",
            destination.display(),
            downloaded_bytes
        );
        Ok(())
    }

    async fn fetch_artifact_bytes_with_retries(
        &self,
        download_url: &str,
    ) -> Result<Vec<u8>, ApplicationError> {
        for attempt in 1..=self.retry_policy.max_attempts() {
            match self.fetch_artifact_bytes_once(download_url).await {
                Ok(bytes) => return Ok(bytes),
                Err(error) if should_retry_download(&error, attempt, self.retry_policy) => {
                    let delay = self.retry_policy.delay_for_attempt(attempt);
                    warn!(
                        "artifact download attempt {}/{} failed for `{download_url}`: {}; retrying in {} ms",
                        attempt,
                        self.retry_policy.max_attempts(),
                        error.error,
                        delay.as_millis()
                    );
                    sleep(delay).await;
                }
                Err(error) => return Err(error.error),
            }
        }

        Err(ApplicationError::External(format!(
            "artifact download retry loop exhausted for `{download_url}`"
        )))
    }

    async fn fetch_artifact_bytes_once(
        &self,
        download_url: &str,
    ) -> Result<Vec<u8>, ArtifactDownloadError> {
        let bytes = self
            .read_response_bytes_with_limit(download_url, self.limits.artifact_max_bytes())
            .await?;
        debug!("fetched {} byte(s) from upstream artifact URL", bytes.len());
        Ok(bytes)
    }

    async fn get_artifact_response(
        &self,
        download_url: &str,
    ) -> Result<reqwest::Response, ArtifactDownloadError> {
        let response = self
            .client
            .get(download_url)
            .send()
            .await
            .map_err(ArtifactDownloadError::from_reqwest)?;
        let status = response.status();
        if !status.is_success() {
            return Err(ArtifactDownloadError {
                error: ApplicationError::External(format!(
                    "upstream artifact request `{download_url}` returned HTTP {status}"
                )),
                retryable: is_retryable_status(status),
            });
        }
        Ok(response)
    }

    async fn read_response_bytes_with_limit(
        &self,
        url: &str,
        limit: u64,
    ) -> Result<Vec<u8>, ArtifactDownloadError> {
        let mut response = self.get_artifact_response(url).await?;
        if let Some(content_length) = response.content_length()
            && content_length > limit
        {
            return Err(ArtifactDownloadError::fatal(format!(
                "upstream response `{url}` content length {content_length} exceeds limit {limit}"
            )));
        }

        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(ArtifactDownloadError::from_reqwest)?
        {
            let next_len = bytes.len().saturating_add(chunk.len());
            if next_len as u64 > limit {
                return Err(ArtifactDownloadError::fatal(format!(
                    "upstream response `{url}` exceeded limit {limit}"
                )));
            }
            bytes.extend_from_slice(&chunk);
        }
        Ok(bytes)
    }
}

fn ensure_content_length_within_limit(
    content_length: Option<u64>,
    expected_size_bytes: u64,
    hard_limit: u64,
    download_url: &str,
) -> Result<(), ArtifactDownloadError> {
    if expected_size_bytes > hard_limit {
        return Err(ArtifactDownloadError::fatal(format!(
            "upstream artifact `{download_url}` declared size {expected_size_bytes} exceeds limit {hard_limit}"
        )));
    }

    if let Some(content_length) = content_length {
        if content_length > hard_limit {
            return Err(ArtifactDownloadError::fatal(format!(
                "upstream artifact `{download_url}` content length {content_length} exceeds limit {hard_limit}"
            )));
        }
        if expected_size_bytes > 0 && content_length > expected_size_bytes {
            return Err(ArtifactDownloadError::fatal(format!(
                "upstream artifact `{download_url}` content length {content_length} exceeds expected size {expected_size_bytes}"
            )));
        }
    }

    Ok(())
}

#[derive(Debug)]
struct ArtifactDownloadError {
    error: ApplicationError,
    retryable: bool,
}

impl ArtifactDownloadError {
    fn retryable(message: impl Into<String>) -> Self {
        Self {
            error: ApplicationError::External(message.into()),
            retryable: true,
        }
    }

    fn fatal(message: impl Into<String>) -> Self {
        Self {
            error: ApplicationError::External(message.into()),
            retryable: false,
        }
    }

    fn from_reqwest(error: reqwest::Error) -> Self {
        let retryable = error.is_timeout()
            || error.is_connect()
            || error.is_body()
            || error.status().is_some_and(is_retryable_status);
        Self {
            error: ApplicationError::External(error.to_string()),
            retryable,
        }
    }
}

fn should_retry_download(
    error: &ArtifactDownloadError,
    attempt: usize,
    policy: ArtifactDownloadRetryPolicy,
) -> bool {
    error.retryable && attempt < policy.max_attempts()
}

fn is_retryable_status(status: StatusCode) -> bool {
    status == StatusCode::REQUEST_TIMEOUT
        || status == StatusCode::TOO_MANY_REQUESTS
        || status == StatusCode::INTERNAL_SERVER_ERROR
        || status == StatusCode::BAD_GATEWAY
        || status == StatusCode::SERVICE_UNAVAILABLE
        || status == StatusCode::GATEWAY_TIMEOUT
}

#[derive(Debug, Deserialize)]
struct PypiResponse {
    info: PypiInfo,
    releases: BTreeMap<String, Vec<PypiReleaseFile>>,
}

#[derive(Debug, Deserialize)]
struct PypiInfo {
    name: String,
    summary: String,
    description: String,
}

#[derive(Debug, Deserialize)]
struct PypiDigests {
    sha256: String,
    blake2b_256: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PypiReleaseFile {
    filename: String,
    packagetype: Option<String>,
    size: u64,
    url: String,
    digests: PypiDigests,
}

fn find_artifact_by_filename<'a>(
    artifacts: &'a [MirroredArtifactSnapshot],
    filename: &str,
) -> Option<&'a MirroredArtifactSnapshot> {
    artifacts
        .iter()
        .find(|artifact| artifact.filename == filename)
}

fn temp_download_path(destination: &Path) -> std::path::PathBuf {
    let temp_name = destination
        .file_name()
        .and_then(|name| name.to_str())
        .map(|name| format!("{name}.part"))
        .unwrap_or_else(|| "download.whl.part".to_string());

    destination.with_file_name(temp_name)
}

#[async_trait]
impl MirrorClient for PypiMirrorClient {
    async fn fetch_project(
        &self,
        project_name: &str,
    ) -> Result<Option<MirroredProjectSnapshot>, ApplicationError> {
        let metadata_url = self.project_metadata_url(project_name)?;
        let payload_url = metadata_url.to_string();
        info!("fetching PyPI metadata for project `{project_name}` from `{metadata_url}`");
        let response = self
            .client
            .get(metadata_url)
            .send()
            .await
            .map_err(|error| ApplicationError::External(error.to_string()))?;

        if response.status() == StatusCode::NOT_FOUND {
            warn!("PyPI returned 404 for project `{project_name}`");
            return Ok(None);
        }

        let payload = response
            .error_for_status()
            .map_err(|error| ApplicationError::External(error.to_string()))?;
        if let Some(content_length) = payload.content_length()
            && content_length > self.limits.metadata_max_bytes()
        {
            return Err(ApplicationError::External(format!(
                "PyPI metadata response `{payload_url}` content length {content_length} exceeds limit {}",
                self.limits.metadata_max_bytes()
            )));
        }
        let mut payload = payload;
        let mut body = Vec::new();
        while let Some(chunk) = payload
            .chunk()
            .await
            .map_err(|error| ApplicationError::External(error.to_string()))?
        {
            let next_len = body.len().saturating_add(chunk.len());
            if next_len as u64 > self.limits.metadata_max_bytes() {
                return Err(ApplicationError::External(format!(
                    "PyPI metadata response `{payload_url}` exceeded limit {}",
                    self.limits.metadata_max_bytes()
                )));
            }
            body.extend_from_slice(&chunk);
        }
        let payload: PypiResponse = serde_json::from_slice(&body)
            .map_err(|error| ApplicationError::External(error.to_string()))?;

        let mut artifacts = Vec::new();
        let mut skipped_file_count = 0usize;
        for (version, files) in payload.releases {
            for file in files {
                if !is_mirrorable_distribution(&file) {
                    skipped_file_count += 1;
                    debug!(
                        "skipping unsupported PyPI release file `{}` with package type {:?}",
                        file.filename, file.packagetype
                    );
                    continue;
                }

                artifacts.push(MirroredArtifactSnapshot {
                    filename: file.filename,
                    version: version.clone(),
                    size_bytes: file.size,
                    sha256: file.digests.sha256,
                    blake2b_256: file.digests.blake2b_256,
                    download_url: file.url,
                    provenance_payload: None,
                });
            }
        }

        debug!(
            "fetched PyPI project `{}` with {} mirrorable artifact(s), skipped {} unsupported file(s)",
            payload.info.name,
            artifacts.len(),
            skipped_file_count
        );
        Ok(Some(MirroredProjectSnapshot {
            canonical_name: payload.info.name,
            summary: payload.info.summary,
            description: payload.info.description,
            artifacts,
        }))
    }

    async fn fetch_artifact_bytes(&self, download_url: &str) -> Result<Vec<u8>, ApplicationError> {
        info!(
            "fetching mirrored artifact bytes from `{download_url}` with up to {} attempt(s)",
            self.retry_policy.max_attempts()
        );
        self.fetch_artifact_bytes_with_retries(download_url).await
    }
}

fn is_mirrorable_distribution(file: &PypiReleaseFile) -> bool {
    if let Some(package_type) = file.packagetype.as_deref() {
        return matches!(
            package_type.trim().to_ascii_lowercase().as_str(),
            "bdist_wheel" | "sdist"
        );
    }

    // Some private PyPI-compatible mirrors omit `packagetype`, so fall back to
    // filename shape while keeping legacy installers like .exe and .egg out.
    is_mirrorable_distribution_filename(&file.filename)
}

fn is_mirrorable_distribution_filename(filename: &str) -> bool {
    filename.ends_with(".whl")
        || filename.ends_with(".tar.gz")
        || filename.ends_with(".tar.bz2")
        || filename.ends_with(".tar.xz")
        || filename.ends_with(".tgz")
        || filename.ends_with(".zip")
}

#[cfg(test)]
mod tests {
    use super::{
        ArtifactDownloadError, ArtifactDownloadRetryPolicy, DEFAULT_MIRROR_ARTIFACT_MAX_BYTES,
        MirrorDownloadLimits, PypiDigests, PypiMirrorClient, PypiReleaseFile,
        find_artifact_by_filename, is_mirrorable_distribution, is_mirrorable_distribution_filename,
        is_retryable_status, should_retry_download, temp_download_path,
    };
    use pyregistry_application::{MirrorClient, MirroredArtifactSnapshot};
    use std::path::{Path, PathBuf};
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use std::time::Duration;
    use tokio::fs;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use uuid::Uuid;

    #[test]
    fn finds_matching_artifact_by_exact_filename() {
        let artifacts = vec![
            MirroredArtifactSnapshot {
                filename: "demo-0.1.0-py3-none-any.whl".into(),
                version: "0.1.0".into(),
                size_bytes: 123,
                sha256: "abc".into(),
                blake2b_256: None,
                download_url: "https://example.test/demo.whl".into(),
                provenance_payload: None,
            },
            MirroredArtifactSnapshot {
                filename: "demo-0.1.0.tar.gz".into(),
                version: "0.1.0".into(),
                size_bytes: 456,
                sha256: "def".into(),
                blake2b_256: None,
                download_url: "https://example.test/demo.tar.gz".into(),
                provenance_payload: None,
            },
        ];

        let artifact = find_artifact_by_filename(&artifacts, "demo-0.1.0-py3-none-any.whl");

        assert_eq!(
            artifact.map(|artifact| artifact.download_url.as_str()),
            Some("https://example.test/demo.whl")
        );
    }

    #[test]
    fn derives_sidecar_part_path_for_downloads() {
        let temp_path = temp_download_path(Path::new("downloads/demo-0.1.0.whl"));

        assert_eq!(temp_path, Path::new("downloads/demo-0.1.0.whl.part"));
    }

    #[test]
    fn temp_download_path_uses_fallback_name_when_destination_has_no_filename() {
        let temp_path = temp_download_path(Path::new("/"));

        assert_eq!(temp_path, Path::new("/download.whl.part"));
    }

    #[test]
    fn default_client_targets_public_pypi_and_policy_exposes_backoff() {
        let client = PypiMirrorClient::default();

        assert_eq!(
            client
                .project_metadata_url("demo")
                .expect("metadata URL")
                .as_str(),
            "https://pypi.org/pypi/demo/json"
        );
        assert_eq!(
            client.retry_policy.initial_backoff(),
            Duration::from_millis(250)
        );
        assert_eq!(
            client.limits.artifact_max_bytes(),
            DEFAULT_MIRROR_ARTIFACT_MAX_BYTES
        );
    }

    #[test]
    fn rejects_invalid_base_urls_and_normalizes_retry_attempts() {
        assert!(PypiMirrorClient::new("not a URL").is_err());

        let policy = ArtifactDownloadRetryPolicy::new(0, Duration::from_millis(5));
        assert_eq!(policy.max_attempts(), 1);
        assert_eq!(
            policy.delay_for_attempt(usize::MAX),
            Duration::from_millis(327_680)
        );
    }

    #[test]
    fn builds_metadata_url_from_configured_base_url() {
        let client =
            PypiMirrorClient::new("https://mirror.example/simple/..").expect("configured base URL");

        let url = client
            .project_metadata_url("demo-pkg")
            .expect("metadata URL");

        assert_eq!(url.as_str(), "https://mirror.example/pypi/demo-pkg/json");
    }

    #[test]
    fn configures_artifact_download_retry_policy_and_limits() {
        let policy = ArtifactDownloadRetryPolicy::new(5, Duration::from_millis(10));
        let limits = MirrorDownloadLimits::new(Duration::from_secs(7), 123, 456);
        let client = PypiMirrorClient::with_retry_policy_and_limits(
            "https://mirror.example",
            policy,
            limits,
        )
        .expect("configured base URL");

        assert_eq!(client.retry_policy.max_attempts(), 5);
        assert_eq!(
            client.retry_policy.delay_for_attempt(1),
            Duration::from_millis(10)
        );
        assert_eq!(
            client.retry_policy.delay_for_attempt(3),
            Duration::from_millis(40)
        );
        assert_eq!(client.limits.http_timeout(), Duration::from_secs(7));
        assert_eq!(client.limits.metadata_max_bytes(), 123);
        assert_eq!(client.limits.artifact_max_bytes(), 456);
    }

    #[test]
    fn classifies_transient_artifact_download_statuses() {
        assert!(is_retryable_status(reqwest::StatusCode::REQUEST_TIMEOUT));
        assert!(is_retryable_status(reqwest::StatusCode::TOO_MANY_REQUESTS));
        assert!(is_retryable_status(reqwest::StatusCode::BAD_GATEWAY));
        assert!(!is_retryable_status(reqwest::StatusCode::NOT_FOUND));
        assert!(!is_retryable_status(reqwest::StatusCode::FORBIDDEN));
    }

    #[test]
    fn classifies_artifact_download_errors_against_policy_limits() {
        let policy = ArtifactDownloadRetryPolicy::new(2, Duration::from_millis(1));
        let retryable = ArtifactDownloadError::retryable("temporary failure");
        let fatal = ArtifactDownloadError::fatal("bad destination");

        assert!(should_retry_download(&retryable, 1, policy));
        assert!(!should_retry_download(&retryable, 2, policy));
        assert!(!should_retry_download(&fatal, 1, policy));
    }

    #[tokio::test]
    async fn retries_transient_artifact_byte_downloads() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test HTTP listener");
        let address = listener.local_addr().expect("listener address");
        let attempts = Arc::new(AtomicUsize::new(0));
        let server_attempts = attempts.clone();
        let server = tokio::spawn(async move {
            for _ in 0..2 {
                let (mut socket, _) = listener.accept().await.expect("accept request");
                let attempt = server_attempts.fetch_add(1, Ordering::SeqCst) + 1;
                let mut buffer = [0_u8; 1024];
                let _ = socket.read(&mut buffer).await.expect("read request");
                let response = if attempt == 1 {
                    "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        .to_string()
                } else {
                    "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
                        .to_string()
                };
                socket
                    .write_all(response.as_bytes())
                    .await
                    .expect("write response");
            }
        });
        let client = PypiMirrorClient::with_retry_policy(
            "https://pypi.org",
            ArtifactDownloadRetryPolicy::new(2, Duration::from_millis(1)),
        )
        .expect("client");

        let bytes = client
            .fetch_artifact_bytes(&format!("http://{address}/demo.whl"))
            .await
            .expect("download should retry and succeed");

        assert_eq!(bytes, b"ok");
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
        server.await.expect("server task");
    }

    #[tokio::test]
    async fn artifact_byte_download_fails_fast_for_non_retryable_status() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test HTTP listener");
        let address = listener.local_addr().expect("listener address");
        let server = serve_http_responses(
            listener,
            vec![http_response(404, "text/plain", b"missing".to_vec())],
        );
        let client = PypiMirrorClient::with_retry_policy(
            "https://pypi.org",
            ArtifactDownloadRetryPolicy::new(3, Duration::from_millis(1)),
        )
        .expect("client");

        let error = client
            .fetch_artifact_bytes(&format!("http://{address}/missing.whl"))
            .await
            .expect_err("404 should not retry");

        assert!(error.to_string().contains("HTTP 404"));
        server.await.expect("server task");
    }

    #[tokio::test]
    async fn artifact_byte_download_rejects_oversized_content_length() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test HTTP listener");
        let address = listener.local_addr().expect("listener address");
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept request");
            let mut buffer = [0_u8; 1024];
            let _ = socket.read(&mut buffer).await.expect("read request");
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                DEFAULT_MIRROR_ARTIFACT_MAX_BYTES + 1
            );
            socket
                .write_all(response.as_bytes())
                .await
                .expect("write response");
        });
        let client = PypiMirrorClient::with_retry_policy(
            "https://pypi.org",
            ArtifactDownloadRetryPolicy::new(1, Duration::from_millis(1)),
        )
        .expect("client");

        let error = client
            .fetch_artifact_bytes(&format!("http://{address}/too-large.whl"))
            .await
            .expect_err("oversized artifact should fail before body allocation");

        assert!(error.to_string().contains("exceeds limit"));
        server.await.expect("server task");
    }

    #[tokio::test]
    async fn downloads_project_artifact_to_destination() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test HTTP listener");
        let address = listener.local_addr().expect("listener address");
        let metadata = pypi_metadata_response(
            "demo",
            &[(
                "1.0.0",
                "demo-1.0.0-py3-none-any.whl",
                "bdist_wheel",
                2,
                &format!("http://{address}/files/demo.whl"),
            )],
        );
        let server = serve_http_responses(
            listener,
            vec![
                http_response(200, "application/json", metadata.into_bytes()),
                http_response(200, "application/octet-stream", b"ok".to_vec()),
            ],
        );
        let client = PypiMirrorClient::with_retry_policy(
            &format!("http://{address}"),
            ArtifactDownloadRetryPolicy::new(1, Duration::from_millis(1)),
        )
        .expect("client");
        let destination = temp_destination("demo-1.0.0-py3-none-any.whl");

        client
            .download_project_artifact_by_filename(
                "demo",
                "demo-1.0.0-py3-none-any.whl",
                &destination,
            )
            .await
            .expect("artifact download");

        assert_eq!(
            fs::read(&destination).await.expect("downloaded bytes"),
            b"ok"
        );
        assert!(
            fs::metadata(temp_download_path(&destination))
                .await
                .is_err(),
            "temporary sidecar should be renamed away"
        );
        server.await.expect("server task");
        cleanup_destination(&destination).await;
    }

    #[tokio::test]
    async fn artifact_file_download_retries_size_mismatch() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test HTTP listener");
        let address = listener.local_addr().expect("listener address");
        let attempts = Arc::new(AtomicUsize::new(0));
        let server_attempts = attempts.clone();
        let metadata = pypi_metadata_response(
            "demo",
            &[(
                "1.0.0",
                "demo-1.0.0.tar.gz",
                "sdist",
                2,
                &format!("http://{address}/files/demo.tar.gz"),
            )],
        );
        let server = tokio::spawn(async move {
            write_response(
                &listener,
                http_response(200, "application/json", metadata.into_bytes()),
            )
            .await;
            for body in [b"x".to_vec(), b"ok".to_vec()] {
                server_attempts.fetch_add(1, Ordering::SeqCst);
                write_response(
                    &listener,
                    http_response(200, "application/octet-stream", body),
                )
                .await;
            }
        });
        let client = PypiMirrorClient::with_retry_policy(
            &format!("http://{address}"),
            ArtifactDownloadRetryPolicy::new(2, Duration::from_millis(1)),
        )
        .expect("client");
        let destination = temp_destination("demo-1.0.0.tar.gz");

        client
            .download_project_artifact_by_filename("demo", "demo-1.0.0.tar.gz", &destination)
            .await
            .expect("download retries after size mismatch");

        assert_eq!(attempts.load(Ordering::SeqCst), 2);
        assert_eq!(
            fs::read(&destination).await.expect("downloaded bytes"),
            b"ok"
        );
        server.await.expect("server task");
        cleanup_destination(&destination).await;
    }

    #[tokio::test]
    async fn artifact_file_download_fails_fast_for_non_retryable_status() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test HTTP listener");
        let address = listener.local_addr().expect("listener address");
        let metadata = pypi_metadata_response(
            "demo",
            &[(
                "1.0.0",
                "demo-1.0.0-py3-none-any.whl",
                "bdist_wheel",
                2,
                &format!("http://{address}/files/demo.whl"),
            )],
        );
        let server = serve_http_responses(
            listener,
            vec![
                http_response(200, "application/json", metadata.into_bytes()),
                http_response(404, "text/plain", b"missing".to_vec()),
            ],
        );
        let client = PypiMirrorClient::with_retry_policy(
            &format!("http://{address}"),
            ArtifactDownloadRetryPolicy::new(3, Duration::from_millis(1)),
        )
        .expect("client");
        let destination = temp_destination("missing.whl");

        let error = client
            .download_project_artifact_by_filename(
                "demo",
                "demo-1.0.0-py3-none-any.whl",
                &destination,
            )
            .await
            .expect_err("404 should not retry");

        assert!(error.to_string().contains("HTTP 404"));
        assert!(fs::metadata(&destination).await.is_err());
        assert!(
            fs::metadata(temp_download_path(&destination))
                .await
                .is_err()
        );
        server.await.expect("server task");
        cleanup_destination(&destination).await;
    }

    #[tokio::test]
    async fn project_artifact_download_reports_missing_project_or_file() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test HTTP listener");
        let address = listener.local_addr().expect("listener address");
        let server = serve_http_responses(
            listener,
            vec![http_response(404, "text/plain", b"missing".to_vec())],
        );
        let client = PypiMirrorClient::with_retry_policy(
            &format!("http://{address}"),
            ArtifactDownloadRetryPolicy::new(1, Duration::from_millis(1)),
        )
        .expect("client");

        assert!(matches!(
            client
                .download_project_artifact_by_filename(
                    "missing",
                    "missing-1.0.0-py3-none-any.whl",
                    &temp_destination("unused.whl"),
                )
                .await,
            Err(pyregistry_application::ApplicationError::NotFound(_))
        ));
        server.await.expect("server task");

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test HTTP listener");
        let address = listener.local_addr().expect("listener address");
        let metadata = pypi_metadata_response(
            "demo",
            &[(
                "1.0.0",
                "demo-1.0.0-py3-none-any.whl",
                "bdist_wheel",
                2,
                &format!("http://{address}/files/demo.whl"),
            )],
        );
        let server = serve_http_responses(
            listener,
            vec![http_response(
                200,
                "application/json",
                metadata.into_bytes(),
            )],
        );
        let client = PypiMirrorClient::with_retry_policy(
            &format!("http://{address}"),
            ArtifactDownloadRetryPolicy::new(1, Duration::from_millis(1)),
        )
        .expect("client");

        assert!(matches!(
            client
                .download_project_artifact_by_filename(
                    "demo",
                    "demo-1.0.0.zip",
                    &temp_destination("unused.zip"),
                )
                .await,
            Err(pyregistry_application::ApplicationError::NotFound(_))
        ));
        server.await.expect("server task");
    }

    #[tokio::test]
    async fn fetch_project_maps_all_versions_and_skips_unsupported_files() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test HTTP listener");
        let address = listener.local_addr().expect("listener address");
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept request");
            let mut buffer = [0_u8; 2048];
            let _ = socket.read(&mut buffer).await.expect("read request");
            let body = serde_json::json!({
                "info": {
                    "name": "Demo_Pkg",
                    "summary": "demo summary",
                    "description": "demo description"
                },
                "releases": {
                    "0.1.0": [
                        {
                            "filename": "demo_pkg-0.1.0-py3-none-any.whl",
                            "packagetype": "bdist_wheel",
                            "size": 2,
                            "url": format!("http://{address}/files/demo.whl"),
                            "digests": {
                                "sha256": "a".repeat(64),
                                "blake2b_256": null
                            }
                        },
                        {
                            "filename": "demo_pkg-0.1.0.exe",
                            "packagetype": "bdist_wininst",
                            "size": 3,
                            "url": format!("http://{address}/files/demo.exe"),
                            "digests": {
                                "sha256": "b".repeat(64),
                                "blake2b_256": null
                            }
                        }
                    ],
                    "0.2.0": [
                        {
                            "filename": "demo_pkg-0.2.0.zip",
                            "packagetype": null,
                            "size": 4,
                            "url": format!("http://{address}/files/demo.zip"),
                            "digests": {
                                "sha256": "c".repeat(64),
                                "blake2b_256": "d".repeat(64)
                            }
                        }
                    ]
                }
            })
            .to_string();
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            socket
                .write_all(response.as_bytes())
                .await
                .expect("write response");
        });
        let client = PypiMirrorClient::new(&format!("http://{address}")).expect("client");

        let project = client
            .fetch_project("demo-pkg")
            .await
            .expect("fetch project")
            .expect("project");

        assert_eq!(project.canonical_name, "Demo_Pkg");
        assert_eq!(project.summary, "demo summary");
        assert_eq!(project.artifacts.len(), 2);
        assert!(
            project
                .artifacts
                .iter()
                .any(|artifact| artifact.version == "0.1.0" && artifact.filename.ends_with(".whl"))
        );
        assert!(
            project
                .artifacts
                .iter()
                .any(|artifact| artifact.version == "0.2.0"
                    && artifact.blake2b_256.as_deref() == Some(&"d".repeat(64)))
        );
        server.await.expect("server task");
    }

    #[tokio::test]
    async fn fetch_project_returns_none_for_404() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test HTTP listener");
        let address = listener.local_addr().expect("listener address");
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept request");
            let mut buffer = [0_u8; 1024];
            let _ = socket.read(&mut buffer).await.expect("read request");
            socket
                .write_all(
                    b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await
                .expect("write response");
        });
        let client = PypiMirrorClient::new(&format!("http://{address}")).expect("client");

        assert!(
            client
                .fetch_project("missing")
                .await
                .expect("fetch")
                .is_none()
        );
        server.await.expect("server task");
    }

    #[test]
    fn filters_legacy_pypi_installers_from_mirroring() {
        let wheel = release_file(
            "pandas-2.3.3-cp314-cp314-manylinux.whl",
            Some("bdist_wheel"),
        );
        let sdist = release_file("pandas-2.3.3.tar.gz", Some("sdist"));
        let legacy_installer = release_file("pandas-0.1.win32-py2.5.exe", Some("bdist_wininst"));
        let egg = release_file("pandas-0.7.0-py2.7.egg", Some("bdist_egg"));

        assert!(is_mirrorable_distribution(&wheel));
        assert!(is_mirrorable_distribution(&sdist));
        assert!(!is_mirrorable_distribution(&legacy_installer));
        assert!(!is_mirrorable_distribution(&egg));
    }

    #[test]
    fn falls_back_to_safe_filename_extensions_when_package_type_is_missing() {
        assert!(is_mirrorable_distribution_filename("demo-1.0.0.tar.gz"));
        assert!(is_mirrorable_distribution_filename("demo-1.0.0.tar.bz2"));
        assert!(is_mirrorable_distribution_filename("demo-1.0.0.tar.xz"));
        assert!(is_mirrorable_distribution_filename("demo-1.0.0.tgz"));
        assert!(is_mirrorable_distribution_filename("demo-1.0.0.zip"));
        assert!(is_mirrorable_distribution_filename(
            "demo-1.0.0-py3-none-any.whl"
        ));
        assert!(!is_mirrorable_distribution_filename("demo-1.0.0.exe"));
        assert!(!is_mirrorable_distribution_filename("demo-1.0.0.egg"));
    }

    fn release_file(filename: &str, packagetype: Option<&str>) -> PypiReleaseFile {
        PypiReleaseFile {
            filename: filename.into(),
            packagetype: packagetype.map(str::to_string),
            size: 0,
            url: "https://files.example.test/demo".into(),
            digests: PypiDigests {
                sha256: "0".repeat(64),
                blake2b_256: None,
            },
        }
    }

    fn pypi_metadata_response(
        project_name: &str,
        files: &[(&str, &str, &str, u64, &str)],
    ) -> String {
        let mut releases = serde_json::Map::new();
        for (version, filename, package_type, size, url) in files {
            releases.insert(
                (*version).to_string(),
                serde_json::json!([{
                    "filename": filename,
                    "packagetype": package_type,
                    "size": size,
                    "url": url,
                    "digests": {
                        "sha256": "0".repeat(64),
                        "blake2b_256": null
                    }
                }]),
            );
        }
        serde_json::json!({
            "info": {
                "name": project_name,
                "summary": "Demo package",
                "description": "Demo package"
            },
            "releases": releases
        })
        .to_string()
    }

    fn http_response(status: u16, content_type: &str, body: Vec<u8>) -> String {
        let reason = match status {
            200 => "OK",
            404 => "Not Found",
            503 => "Service Unavailable",
            _ => "Status",
        };
        format!(
            "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            String::from_utf8(body).expect("test response body is utf8")
        )
    }

    fn serve_http_responses(
        listener: TcpListener,
        responses: Vec<String>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            for response in responses {
                write_response(&listener, response).await;
            }
        })
    }

    async fn write_response(listener: &TcpListener, response: String) {
        let (mut socket, _) = listener.accept().await.expect("accept request");
        let mut buffer = [0_u8; 2048];
        let _ = socket.read(&mut buffer).await.expect("read request");
        socket
            .write_all(response.as_bytes())
            .await
            .expect("write response");
    }

    fn temp_destination(filename: &str) -> PathBuf {
        std::env::temp_dir()
            .join(format!("pyregistry-mirror-{}", Uuid::new_v4()))
            .join(filename)
    }

    async fn cleanup_destination(destination: &Path) {
        if let Some(parent) = destination.parent() {
            let _ = fs::remove_dir_all(parent).await;
        }
    }
}
