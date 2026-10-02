use std::time::Duration;

use tokio::task::JoinSet;

/// Run `future` with a millisecond deadline. `None` means the deadline fired.
pub async fn run<T>(timeout_ms: u64, future: impl std::future::Future<Output = T>) -> Option<T> {
    tokio::time::timeout(Duration::from_millis(timeout_ms), future)
        .await
        .ok()
}

/// Resolve when the process should stop: Ctrl-C everywhere, plus SIGTERM on
/// Unix so containers and service managers shut scans down cleanly.
pub async fn interrupted() {
    #[cfg(unix)]
    {
        if let Ok(mut terminate) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = terminate.recv() => {}
            }
            return;
        }
    }
    let _ = tokio::signal::ctrl_c().await;
}

/// Drain a `JoinSet`, collecting results. An interrupt aborts in-flight tasks
/// and reports `cancelled` so the caller can return partial results instead
/// of hanging.
pub async fn join_cancellable<T: Send + 'static>(set: &mut JoinSet<T>) -> (Vec<T>, usize, bool) {
    let mut items = Vec::new();
    let mut join_errors = 0usize;
    loop {
        tokio::select! {
            biased;
            _ = interrupted() => {
                set.abort_all();
                return (items, join_errors, true);
            }
            next = set.join_next() => match next {
                None => return (items, join_errors, false),
                Some(Ok(item)) => items.push(item),
                Some(Err(_)) => join_errors += 1,
            },
        }
    }
}
