use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Smooth rate limiter: operations may *start* at most `per_sec` times per
/// second, evenly spaced (burst of one). Independent from the concurrency
/// semaphore, which caps how many operations are *active*.
pub struct RateLimiter {
    period: Duration,
    next_allowed: Mutex<Instant>,
}

impl RateLimiter {
    /// `per_sec` must be non-zero (validated with the rest of the limits).
    pub fn new(per_sec: u64) -> Self {
        let period = Duration::from_secs(1).checked_div(per_sec.max(1) as u32);
        Self {
            period: period.unwrap_or(Duration::from_nanos(1)),
            next_allowed: Mutex::new(Instant::now()),
        }
    }

    /// Wait until this operation is allowed to start.
    pub async fn acquire(&self) {
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
}
