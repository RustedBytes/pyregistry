use crate::ApplicationError;
use async_lock::Mutex;
use futures_channel::oneshot;
use std::sync::{Arc, LazyLock};

// Shared across app instances and both artifact paths. Admission happens before
// submitting to Rayon, so its queue cannot accumulate expanded archives.
static ADMISSION: LazyLock<Arc<Mutex<()>>> = LazyLock::new(|| Arc::new(Mutex::new(())));
static POOL: LazyLock<Result<rayon::ThreadPool, String>> = LazyLock::new(|| {
    rayon::ThreadPoolBuilder::new()
        .num_threads(1)
        .thread_name(|_| "artifact-cpu".into())
        .build()
        .map_err(|error| error.to_string())
});

pub(crate) async fn run<T: Send + 'static>(
    work: impl FnOnce() -> Result<T, ApplicationError> + Send + 'static,
) -> Result<T, ApplicationError> {
    let permit = ADMISSION.lock_arc().await;
    let pool = POOL
        .as_ref()
        .map_err(|error| ApplicationError::External(error.clone()))?;
    let (sender, receiver) = oneshot::channel();
    pool.spawn(move || {
        // Cancellation cannot release admission while the worker still runs.
        let _permit = permit;
        let result =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(work)).unwrap_or_else(|_| {
                Err(ApplicationError::External(
                    "artifact CPU worker panicked".into(),
                ))
            });
        let _ = sender.send(result);
    });
    receiver
        .await
        .map_err(|_| ApplicationError::External("artifact CPU worker stopped".into()))?
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test(flavor = "current_thread")]
    async fn worker_keeps_executor_live_and_admission_survives_cancellation() {
        let (started_tx, started_rx) = oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let first = tokio::spawn(run(move || {
            let _ = started_tx.send(());
            release_rx.recv().unwrap();
            Ok(())
        }));
        tokio::time::timeout(Duration::from_secs(5), started_rx)
            .await
            .unwrap()
            .unwrap();
        first.abort();
        let _ = first.await;
        let (second_tx, mut second_rx) = oneshot::channel();
        let second = tokio::spawn(run(move || {
            let _ = second_tx.send(());
            Ok(7)
        }));
        // Timer progress while a synchronous worker is blocked, and no second
        // CPU job even after the first request's future has been cancelled.
        tokio::time::sleep(Duration::from_millis(20)).await;
        let premature = second_rx.try_recv().unwrap().is_some();
        release_tx.send(()).unwrap();
        assert!(!premature, "cancellation released active CPU admission");
        assert_eq!(second.await.unwrap().unwrap(), 7);
        let error = run(|| -> Result<(), ApplicationError> { panic!("test worker panic") }).await;
        assert!(matches!(error, Err(ApplicationError::External(_))));
        assert_eq!(run(|| Ok(9)).await.unwrap(), 9, "panic leaked admission");
        let error =
            run(|| Err::<(), _>(ApplicationError::Conflict("invalid archive".into()))).await;
        assert!(matches!(error, Err(ApplicationError::Conflict(_))));
    }
}
