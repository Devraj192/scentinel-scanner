use std::sync::Arc;
use std::time::Duration;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use sentinelscan::config::Limits;
use sentinelscan::safety::scope::{parse_targets, ScopeGuard};
use sentinelscan::scanner::rate_limit::RateLimiter;
use sentinelscan::scanner::scheduler::scan_ports;
use tokio::net::TcpListener;
use tokio::runtime::Runtime;
use tokio::sync::Semaphore;

/// Local lab only: listeners on 127.0.0.1 that accept and hold briefly.
async fn lab_listeners(count: usize) -> Vec<u16> {
    let mut ports = Vec::with_capacity(count);
    for _ in 0..count {
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
    ports
}

fn lab_limits() -> Limits {
    Limits {
        max_concurrency: 100,
        max_rate: 100_000,
        connect_timeout_ms: 2000,
        probe_timeout_ms: 2000,
        ..Limits::default()
    }
}

fn lab_guard() -> ScopeGuard {
    let targets = parse_targets(&["127.0.0.1".to_owned()], false, 256).expect("lab scope");
    ScopeGuard::from_targets(&targets)
}

fn bench_port_scan(criterion: &mut Criterion) {
    let runtime = Runtime::new().expect("tokio runtime");
    let mut group = criterion.benchmark_group("port_scan");
    for count in [16u16, 64u16] {
        group.throughput(Throughput::Elements(u64::from(count)));
        group.bench_with_input(
            BenchmarkId::from_parameter(count),
            &count,
            |bench, &count| {
                bench.to_async(&runtime).iter(|| async {
                    let ports = lab_listeners(usize::from(count)).await;
                    let limits = lab_limits();
                    let guard = lab_guard();
                    let rate = Arc::new(RateLimiter::new(limits.max_rate));
                    let ips = vec!["127.0.0.1".parse().expect("ip")];
                    let skip = std::collections::HashSet::new();
                    let scan = scan_ports(&ips, &ports, &limits, &guard, rate, &skip).await;
                    assert_eq!(scan.probes.len(), usize::from(count));
                    scan
                });
            },
        );
    }
    group.finish();
}

fn bench_discovery(criterion: &mut Criterion) {
    let runtime = Runtime::new().expect("tokio runtime");
    let mut group = criterion.benchmark_group("host_discovery");
    group.throughput(Throughput::Elements(8));
    group.bench_function("discover_8_hosts", |bench| {
        bench.to_async(&runtime).iter(|| async {
            let ports = lab_listeners(1).await;
            let limits = lab_limits();
            let guard = lab_guard();
            let semaphore = Arc::new(Semaphore::new(limits.max_concurrency));
            let rate = Arc::new(RateLimiter::new(limits.max_rate));
            let ips = vec!["127.0.0.1".parse().expect("ip"); 8];
            let (hosts, _) = sentinelscan::discovery::host::discover_all(
                &ips, &ports, &limits, &guard, semaphore, rate,
            )
            .await;
            assert_eq!(hosts.len(), 8);
            hosts
        });
    });
    group.finish();
}

fn bench_detection(criterion: &mut Criterion) {
    let detectors = sentinelscan::detection::all();
    let banners: Vec<&[u8]> = vec![
        b"SSH-2.0-OpenSSH_9.3p1 Debian\r\n",
        b"220 (vsFTPd 3.0.3)\r\n",
        b"220 mail.example.com ESMTP Postfix\r\n",
        b"HTTP/1.1 200 OK\r\nServer: TestLab/1.2.3\r\n\r\n",
        b"\x00\xff\x1b garbage bytes here",
    ];
    let mut group = criterion.benchmark_group("detection");
    group.throughput(Throughput::Elements(banners.len() as u64));
    group.bench_function("match_banners", |bench| {
        bench.iter(|| {
            for banner in &banners {
                for detector in &detectors {
                    if detector.match_banner(banner, 80).is_some() {
                        break;
                    }
                }
            }
        });
    });
    group.finish();
}

criterion_group!(benches, bench_port_scan, bench_discovery, bench_detection);
criterion_main!(benches);
