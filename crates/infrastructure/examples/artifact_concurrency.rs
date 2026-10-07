//! Isolated production CPU stages; no database, network, storage or classifier.
use futures_util::{StreamExt, stream};
use pyregistry_application::*;
use pyregistry_infrastructure::*;
use std::{
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

struct MemoryReader(Arc<Vec<u8>>);
impl WheelArchiveReader for MemoryReader {
    fn read_wheel(&self, _: &Path) -> Result<WheelArchiveSnapshot, ApplicationError> {
        ZipWheelArchiveReader.read_wheel_bytes("demo.whl", &self.0)
    }
    fn read_wheel_bytes(
        &self,
        name: &str,
        bytes: &[u8],
    ) -> Result<WheelArchiveSnapshot, ApplicationError> {
        ZipWheelArchiveReader.read_wheel_bytes(name, bytes)
    }
}
fn audit(reader: Arc<dyn WheelArchiveReader>) -> WheelAuditUseCase {
    WheelAuditUseCase::new(
        reader,
        Arc::new(YaraWheelVirusScanner::from_rules_dir(
            "supplied/signature-base/yara",
        )),
        Arc::new(FoxGuardWheelSourceSecurityScanner::default()),
    )
}
fn main() -> anyhow::Result<()> {
    let args: Vec<_> = std::env::args().collect();
    anyhow::ensure!(
        args.len() == 6 || args.len() == 7,
        "artifact_concurrency WHEEL inline|offload upload|audit|mixed CONCURRENCY JOBS [ASYNC_WORKERS]"
    );
    let bytes = std::fs::read(&args[1])?;
    let offload = match args[2].as_str() {
        "inline" => false,
        "offload" => true,
        _ => anyhow::bail!("invalid mode"),
    };
    let kind = args[3].clone();
    anyhow::ensure!(
        ["upload", "audit", "mixed"].contains(&kind.as_str()),
        "invalid workload"
    );
    let concurrency: usize = args[4].parse()?;
    let jobs: usize = args[5].parse()?;
    anyhow::ensure!(concurrency > 0 && jobs > 0, "positive counts required");
    let workers: usize = args.get(6).map_or(Ok(1), |value| value.parse())?;
    anyhow::ensure!(workers > 0, "positive worker count required");
    // Model a ready request burst. Input preparation must not masquerade as
    // event-loop stalls from inspection/audit. RSS still includes these buffers.
    let payloads: Vec<_> = (0..jobs).map(|_| bytes.clone()).collect();
    drop(bytes);
    let runtime = if workers == 1 {
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()?
    } else {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(workers)
            .enable_time()
            .build()?
    };
    runtime.block_on(async {
        let done = Arc::new(AtomicBool::new(false));
        let stop = done.clone();
        let (armed_tx, armed_rx) = tokio::sync::oneshot::channel();
        let heartbeat = tokio::spawn(async move {
            let period = Duration::from_millis(1);
            let mut delays = Vec::new();
            let mut deadline = tokio::time::Instant::now() + period;
            let _ = armed_tx.send(());
            loop {
                tokio::time::sleep_until(deadline).await;
                let now = tokio::time::Instant::now();
                delays.push(now.saturating_duration_since(deadline).as_secs_f64() * 1000.0);
                if stop.load(Ordering::Relaxed) { break; }
                deadline = now + period;
            }
            delays
        });
        // Arm the independent heartbeat before any synchronous stage can run.
        armed_rx.await?;
        let start = Instant::now();
        let inspector = Arc::new(FilesystemDistributionInspector);
        let mut latencies = stream::iter(payloads.into_iter().enumerate()).map(|(index, payload)| {
            let inspector = inspector.clone();
            let kind = kind.clone();
            let start = Instant::now();
            let task = tokio::spawn(async move {
                let upload = kind == "upload" || (kind == "mixed" && index % 2 == 0);
                if upload {
                    if offload {
                        std::hint::black_box(DistributionValidationUseCase::new(inspector).inspect_bytes("demo.whl".into(), payload).await?);
                    } else {
                        std::hint::black_box(inspector.inspect_distribution_bytes("demo.whl", &payload)?);
                    }
                } else if offload {
                    std::hint::black_box(audit(Arc::new(ZipWheelArchiveReader)).audit_bytes("demo".into(), "demo.whl".into(), payload).await?);
                } else {
                    std::hint::black_box(audit(Arc::new(MemoryReader(Arc::new(payload)))).audit(AuditWheelCommand { project_name: "demo".into(), wheel_path: PathBuf::from("demo.whl") })?);
                }
                Ok::<_, ApplicationError>(start.elapsed().as_secs_f64() * 1000.0)
            });
            async move { task.await.map_err(|error| ApplicationError::External(error.to_string()))? }
        }).buffer_unordered(concurrency).collect::<Vec<_>>().await.into_iter().collect::<Result<Vec<_>, _>>()?;
        let seconds = start.elapsed().as_secs_f64();
        done.store(true, Ordering::Relaxed);
        let mut delays = heartbeat.await?;
        latencies.sort_by(f64::total_cmp);
        delays.sort_by(f64::total_cmp);
        let percentile = |values: &[f64], p: f64| values[((values.len() - 1) as f64 * p).ceil() as usize];
        println!("{{\"async_workers\":{},\"mode\":\"{}\",\"workload\":\"{}\",\"concurrency\":{},\"jobs\":{},\"seconds\":{},\"jobs_per_second\":{},\"job_p99_ms\":{},\"heartbeat_samples\":{},\"heartbeat_p99_ms\":{},\"heartbeat_max_ms\":{}}}", workers, args[2], kind, concurrency, jobs, seconds, jobs as f64 / seconds, percentile(&latencies, 0.99), delays.len(), percentile(&delays, 0.99), delays.last().unwrap());
        Ok::<_, anyhow::Error>(())
    })
}
