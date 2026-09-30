use std::time::Duration;

use tokio::task::JoinSet;

/// Run `future` with a millisecond deadline. `None` means the deadline fired.
pub async fn run<T>(timeout_ms: u64, future: impl std::future::Future<Output = T>) -> Option<T> {
    tokio::time::timeout(Duration::from_millis(timeout_ms), future)
        .await
        .ok()
}

/// Drain a `JoinSet`, collecting results. A second Ctrl-C (or first) aborts
/// in-flight tasks and reports `cancelled` so the caller can return partial
/// results instead of hanging.
pub async fn join_cancellable<T: Send + 'static>(set: &mut JoinSet<T>) -> (Vec<T>, usize, bool) {
    let mut items = Vec::new();
    let mut join_errors = 0usize;
    loop {
        tokio::select! {
            biased;
            _ = tokio::signal::ctrl_c() => {
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
