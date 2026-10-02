use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::time::{Duration, Instant};

/// Smooth rate limiter: operations may *start* at most `per_sec` times per
/// second, evenly spaced (burst of one). Independent from the concurrency
/// semaphore, which caps how many operations are *active*.
///
/// Every network operation in the engine passes through `acquire`, so holding
/// the pause flag pauses all new traffic at one choke point while in-flight
/// operations finish. The TUI pause key drives this.
pub struct RateLimiter {
    period: Duration,
    next_allowed: Mutex<Instant>,
    paused: Arc<AtomicBool>,
}

impl RateLimiter {
    /// `per_sec` must be non-zero (validated with the rest of the limits).
    pub fn new(per_sec: u64) -> Self {
        Self::with_pause(per_sec, Arc::new(AtomicBool::new(false)))
    }

    /// Share an external pause flag, so one toggle pauses every limiter
    /// built from it.
    pub fn with_pause(per_sec: u64, paused: Arc<AtomicBool>) -> Self {
        let period = Duration::from_secs(1).checked_div(per_sec.max(1) as u32);
        Self {
            period: period.unwrap_or(Duration::from_nanos(1)),
            next_allowed: Mutex::new(Instant::now()),
            paused,
        }
    }

    /// Pause or resume the start of new operations. Pausing never cancels
    /// anything already running.
    pub fn set_paused(&self, paused: bool) {
        self.paused.store(paused, Ordering::SeqCst);
    }

    /// Wait until this operation is allowed to start.
    pub async fn acquire(&self) {
        while self.paused.load(Ordering::SeqCst) {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let wait = {
            let mut next = self
                .next_allowed
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let now = Instant::now();
            if now >= *next {
                *next = now + self.period;
                Duration::ZERO
            } else {
                let wait = *next - now;
                *next += self.period;
                wait
            }
        };
        if !wait.is_zero() {
            tokio::time::sleep(wait).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn caps_start_rate() {
        let limiter = RateLimiter::new(20);
        let start = Instant::now();
        for _ in 0..5 {
            limiter.acquire().await;
        }
        assert!(start.elapsed() >= Duration::from_millis(150));
    }

    #[tokio::test]
    async fn pause_blocks_starts_until_released() {
        use tokio::time::timeout;
        let limiter = RateLimiter::new(100_000);
        limiter.set_paused(true);
        assert!(
            timeout(Duration::from_millis(200), limiter.acquire())
                .await
                .is_err(),
            "paused limiter must not admit operations"
        );
        limiter.set_paused(false);
        assert!(
            timeout(Duration::from_secs(2), limiter.acquire())
                .await
                .is_ok(),
            "released limiter must admit operations"
        );
    }
}
