//! Lab statistics: ports/sec, hosts/sec, and probe-latency percentiles against
//! local listeners only. Run with `cargo run --release --example labstats`.

use std::sync::Arc;
use std::time::{Duration, Instant};

use sentinelscan_core::config::Limits;
use sentinelscan_core::safety::scope::{parse_targets, ScopeGuard};
use sentinelscan_core::scanner::rate_limit::RateLimiter;
use sentinelscan_core::scanner::scheduler::scan_ports;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;

fn percentile(sorted: &mut [u64], percent: usize) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    sorted.sort_unstable();
    let index = (sorted.len() - 1) * percent / 100;
    sorted[index]
}

#[tokio::main]
async fn main() {
    let targets = parse_targets(&["127.0.0.1".to_owned()], false, 256).expect("lab scope");
    let guard = ScopeGuard::from_targets(&targets);
    let limits = Limits {
        max_concurrency: 100,
        max_rate: 100_000,
        ..Limits::default()
    };

    // 64 open ports on loopback.
    let mut ports = Vec::new();
    for _ in 0..64 {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind lab");
        ports.push(listener.local_addr().expect("addr").port());
        tokio::spawn(async move {
            loop {
                let Ok((socket, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                    drop(socket);
                });
            }
        });
    }

    let rate = Arc::new(RateLimiter::new(limits.max_rate));
    let skip = std::collections::HashSet::new();
    let ips = vec!["127.0.0.1".parse().expect("ip")];
    let start = Instant::now();
    let scan = scan_ports(&ips, &ports, &limits, &guard, rate, &skip).await;
    let elapsed = start.elapsed();
    let mut latencies: Vec<u64> = scan
        .probes
        .iter()
        .map(|probe| probe.outcome.latency_ms)
        .collect();
    let ports_per_sec = scan.probes.len() as f64 / elapsed.as_secs_f64();
    println!(
        "ports: {} in {:.2?} = {:.0}/sec",
        scan.probes.len(),
        elapsed,
        ports_per_sec
    );
    println!(
        "probe latency ms: p50={} p95={} p99={}",
        percentile(&mut latencies, 50),
        percentile(&mut latencies, 95),
        percentile(&mut latencies, 99)
    );

    let semaphore = Arc::new(Semaphore::new(limits.max_concurrency));
    let rate = Arc::new(RateLimiter::new(limits.max_rate));
    let ips = vec!["127.0.0.1".parse().expect("ip"); 8];
    let start = Instant::now();
    let (hosts, _) = sentinelscan_core::discovery::host::discover_all(
        &ips,
        &ports[..1],
        &limits,
        &guard,
        semaphore,
        rate,
    )
    .await;
    let elapsed = start.elapsed();
    println!(
        "hosts: {} in {:.2?} = {:.0}/sec",
        hosts.len(),
        elapsed,
        hosts.len() as f64 / elapsed.as_secs_f64()
    );
    println!(
        "memory by construction: banner buffers capped at {} bytes x {} concurrent probes",
        limits.max_banner_size, limits.max_concurrency
    );
}
