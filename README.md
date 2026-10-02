# SentinelScan

[![ci](https://github.com/Devraj192/sentinel-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/Devraj192/sentinel-scanner/actions/workflows/ci.yml)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A command-line TCP port scanner for networks you are allowed to test. It
discovers live hosts, classifies port states honestly, identifies services
with evidence attached, estimates the OS from banners, and stores every scan
in local SQLite history for comparison.

> **Authorized use only.** Run SentinelScan only against systems and networks
> you own or have written permission to test. Every run prints this warning
> with the exact scope and asks for confirmation before sending traffic.

## Contents

- [Quick start](#quick-start)
- [Commands](#commands)
- [Port states](#port-states)
- [Service and OS detection](#service-and-os-detection)
- [Profiles](#profiles)
- [Scan traffic](#scan-traffic)
- [Operations](#operations)
- [History, compare, resume](#history-compare-resume)
- [Configuration](#configuration)
- [Output formats](#output-formats)
- [Library use](#library-use)
- [Benchmarks](#benchmarks)
- [Limitations](#limitations)
- [Safety model](#safety-model)
- [Development](#development)
- [License](#license)

## Quick start

Requires Rust stable. No system dependencies (SQLite is bundled).

```sh
cargo build --release
./target/release/sentinelscan scan 127.0.0.1 --ports 22,80,443 --profile quick --yes --skip-host-discovery
```

Output:

```text
Authorized use only: scan only systems you own or have written permission to test.
scan_id: 01HEXAMPLE...
targets: 127.0.0.1
hosts: 1
ports: 22,80,443 (3 selected)
concurrency: 50
rate: 500/s
output: terminal
HOST        PORT    STATE   SERVICE
127.0.0.1   22      closed  -
127.0.0.1   80      closed  -
127.0.0.1   443     closed  -
```

Start something to find — e.g. `python -m http.server 8000` in another
terminal — then scan it with the default Standard profile to see service
detection:

```sh
./target/release/sentinelscan scan 127.0.0.1 --ports 8000 --yes --skip-host-discovery
```

## Commands

```text
sentinelscan scan <target> [--ports 1-1024] [--profile quick|standard|custom]
                           [--concurrency 100] [--rate 500]
                           [--service-detection] [--banner] [--os-detection]
                           [--output terminal|json|csv]
                           [--skip-host-discovery] [--allow-hostnames]
                           [--config FILE] [--db FILE] [--resume SCAN_ID] [--yes]
sentinelscan hosts <target> [--allow-hostnames] [--yes]
sentinelscan ports <target> [--allow-hostnames] [--yes]
sentinelscan services <target> [--allow-hostnames] [--yes]
sentinelscan history [--db FILE] [--output terminal|json]
sentinelscan compare <scan_a> <scan_b> [--db FILE] [--output terminal|json]
sentinelscan config [--config FILE]
```

- `scan` — full pipeline: scope confirmation, host discovery, port scan,
  service detection, OS estimate, stored to history.
- `hosts` — discovery only (`HOST / STATUS / LATENCY_MS`).
- `ports` — discovery plus port scan, no detection.
- `services` — discovery plus port scan plus detection
  (`HOST / PORT / SERVICE / VERSION / CONFIDENCE`, plus OS lines).
- `history` — list stored scans with host and open-port counts.
- `compare` — diff two scans: added, removed, and changed ports/services.
- `config` — print the effective configuration as TOML.

Targets accept IPv4, IPv6, CIDR ranges, and multiple values
(`scan 127.0.0.1 10.0.0.0/30 --ports 22,80-85,443`). Hostnames are rejected
unless `--allow-hostnames` is passed.

Ports accept a single port (`22`), a list (`80,443,8080`), a range
(`1-1024`), a mix (`22,80-85,443`), or a named set:

| Name       | Ports                        |
| ---------- | ---------------------------- |
| `quick`    | 80, 443                      |
| `standard` | 22, 80, 443, 8080, 8443      |
| `full`     | 1–1024                       |

## Port states

| Observed outcome                        | State      | Stored reason          |
| --------------------------------------- | ---------- | ---------------------- |
| TCP handshake completes                 | `open`     | `handshake`            |
| Connection actively refused (RST)       | `closed`   | `refused`              |
| Timeout with no response                | `filtered` | `timeout`              |
| ICMP unreachable / prohibited           | `filtered` | `host_unreachable` etc |
| Local error (permission, exhaustion)    | `unknown`  | `local_error`          |

A timeout is never reported as `closed`. Every result keeps its raw reason.

## Service and OS detection

Detection runs under the Standard profile, with `--service-detection` or
`--banner`, or when enabled in the config file. The Quick profile skips it.
Only open ports are probed, passive banners first, at most one active probe
per detector, first match wins.

| Detector | Method | Version source |
| -------- | ------ | -------------- |
| SSH      | passive `SSH-2.0-*` banner | software token, e.g. `OpenSSH_9.3p1` |
| FTP      | passive `220` greeting | `Name x.y` when present, else unknown |
| SMTP     | passive `220` greeting with mail tokens | same heuristic, else unknown |
| HTTP     | one minimal `GET /` | `Server` header, else unknown |
| HTTPS    | TLS-alert reply to that `GET`, or alert bytes | always unknown |
| DNS      | one `version.bind` TXT query over TCP | TXT string, e.g. `BIND 9.18.x` |
| Generic  | fallback | unknown, confidence 0 |

No authentication attempts, no destructive commands. Banner reads are capped
by `max_banner_size` and `probe_timeout_ms`; oversized banners are truncated
and flagged.

OS estimates use detected services and banners only — no raw sockets. A
distro token (`Ubuntu 22.04`, `Microsoft-IIS/10.0`) suggests a family with
confidence capped at 0.65; an SSH banner alone yields weak `Unix-like`; thin
evidence yields `Unknown` with confidence 0. Every guess lists observation
and inference evidence separately. Confidence scores are the detector's own
0.0–1.0 scale, not verified probabilities.

## Profiles

| Profile    | Ports          | Detection | OS estimate |
| ---------- | -------------- | --------- | ----------- |
| `quick`    | `quick` set    | off       | off         |
| `standard` | `standard` set | on        | on          |
| `custom`   | `standard` set | off       | off         |

Explicit flags beat config-file `[profiles.*]` tables, which beat these
built-ins. `--os-detection` implies service detection, since detection
supplies the OS signals.

## Scan traffic

Know what a run sends before approving the scope prompt:

- Host discovery: up to 4 TCP connects per host (fewer when the port list is
  shorter), skipped entirely with `--skip-host-discovery`.
- Port scan: exactly one TCP connect per host × port.
- Service detection, per **open** port only: one passive banner connection,
  then at most one HTTP `GET` and one DNS `version.bind` query, each only
  while no earlier detector matched. Closed, filtered, and unknown ports
  cost nothing here.
- OS estimation and output rendering send nothing.

A default Standard scan of one host × 100 closed ports is ~104 connects;
every open port adds 1–3 more.

## Operations

**IPv6.** Parsed like IPv4, including CIDR (`::1`, `fd00::/64`), and scanned
the same way. Zone IDs (`fe80::1%eth0`) are rejected: neither the address
parser nor hostname syntax accepts `%`. Lab coverage is loopback (`::1`).

**DNS.** Hostnames are rejected unless `--allow-hostnames` is passed. After
scope confirmation, each hostname resolves once via async lookup and every
returned IP is scanned. A name that fails to resolve stays in the report as
`unknown`; the scan continues.

**SQLite locking.** Each storage call opens its own short-lived connection
with a 5-second busy timeout, and each scan phase commits in one
transaction, so two scans sharing a `--db` file wait briefly instead of
failing. For heavy parallel automation, prefer one `--db` per job.

**Interrupted scans.** Ctrl-C and overall-timeout leave the scan `running`
with a printed resume hint; SIGKILL leaves the same state by construction.
`scan --resume <id>` reuses the stored scope and skips every saved probe.
Finished scans refuse to resume.

**Output compatibility.** JSON follows the canonical model: `meta`
(`scan_id`, `version`, `started/finished_unix_secs`, `truncated`,
`peak_active_probes`), `targets`, and `hosts[]` with `address`, `status`,
`latency_ms`, `ports[]`, and nullable `os`. `banner.raw` never serializes;
only the sanitized `text` is stored. `service`, `version`, and `confidence`
are null until detection runs. CSV columns are fixed
(`scan_id,host,port,protocol,state,reason,service,version,confidence`) with
RFC 4180 quoting. Terminal tables are human views and may gain columns;
scripts should read JSON or CSV.

## History, compare, resume

Every `scan` (including `ports` and `services` runs) persists to SQLite at
`.sentinelscan/history.db` in the working directory; `--db` overrides the
path. On Unix the directory is created `0o700` and the file `0o600`; on
Windows the file inherits your user ACLs.

- `history` lists scan id, status, targets, host count, open-port count.
- `compare A B` treats A as baseline: ports only in B are `added`, only in
  A are `removed`, and state/service/version differences are `changed`.
- Interrupted scans (Ctrl-C, overall timeout) stay `running` with a printed
  resume hint. `scan --resume <id> --yes` reuses the stored scope and saved
  probes and only probes what is missing. `--resume` cannot be combined with
  targets or `--ports`, and finished scans refuse to resume.

Reloading a stored scan reproduces the original result exactly (raw banner
bytes are the one exception: they exist only for in-memory matching and are
never persisted).

## Configuration

`--config` points at a TOML file. Every field is optional; missing fields
fall back to the defaults.

```toml
[limits]
max_hosts = 256            # total hosts; CIDR expansion is checked first
max_ports = 1024           # total ports per scan
max_concurrency = 50       # simultaneously active operations (1-5000)
max_rate = 500             # operations started per second (1-100000)
connect_timeout_ms = 3000
probe_timeout_ms = 2000    # banner reads and detection probes
max_banner_size = 4096     # banner bytes kept per port
max_scan_duration_secs = 300  # overall deadline; expiry stays resumable

[profiles.quick]
ports = "80,443"
service_detection = false

[profiles.standard]
service_detection = true
```

`--concurrency` and `--rate` override the file. `sentinelscan config` prints
the effective configuration, including profile tables.

## Output formats

- `terminal` (default): `HOST / PORT / STATE / SERVICE` table, plus `os`
  lines when an OS guess was decided. Control characters are stripped before
  printing, so hostile banners cannot corrupt the terminal.
- `json`: the canonical result model, pretty-printed.
- `csv`: one row per scanned port, RFC 4180 quoting.

`json` and `csv` keep stdout pure machine-readable output: the scope summary
and all logs go to stderr. Structured logs (`scan_started`,
`host_discovered`, `port_open`, `service_detected`, `timeout`,
`scan_completed`) follow `RUST_LOG`, defaulting to `info`.

## Library use

The binary is a thin CLI over a reusable library:

```rust
use sentinelscan::{Config, Storage};

let config = Config::load(None)?; // conservative defaults, always valid
let storage = Storage::open(std::path::Path::new(".sentinelscan/history.db"))?;
for scan in storage.list_scans()? {
    println!("{} {} ({} open)", scan.scan_id, scan.status, scan.open_port_count);
}
# Ok::<(), sentinelscan::Error>(())
```

## Benchmarks

Controlled lab (loopback listeners, release profile, dev machine — rerun
yours with `cargo bench` and `cargo run --release --example labstats`):

| Metric | Result |
| ------ | ------ |
| Port scan throughput | ~190 ports/sec |
| Host discovery | ~660 hosts/sec |
| Passive banner matching | ~1.5 M/sec |
| Probe latency p50 / p95 / p99 | 0 ms / 0 ms / 2 ms |

Memory is bounded by construction rather than profiler: at most
`max_banner_size` bytes per probe × `max_concurrency` concurrent probes
(~200 KB at defaults), plus one row per probed port in SQLite.

## Limitations

Honest boundaries, by design:

- TCP connect scans only. No UDP, no ICMP discovery, no raw-packet OS
  techniques (they need privileges this tool does not assume).
- HTTPS is recognized, never negotiated: no TLS handshake is performed,
  so its version is always `unknown`.
- DNS detection is one TCP `version.bind` query; most DNS lives on UDP and
  is out of scope.
- Host discovery uses TCP probes: a host behind a firewall that drops
  everything reads as `down`, and fully silent targets read as `filtered`
  ports rather than `closed` (observed behavior, never a guess).
- OS families come from banner tokens only; anything without an explicit
  token is `Unknown`.
- History is a local file, not a server: concurrent writers share one
  SQLite file with one connection per operation.

## Safety model

- Every socket operation passes through `ScopeGuard`, built from the
  confirmed scope. No code path opens a connection without it.
- Testing targets are `127.0.0.1`, `::1`, or networks you own. Never scan
  anything else with this tool.
- No exploitation, credential guessing, brute forcing, denial of service,
  evasion, or destructive protocol commands — none exist in this codebase.
- All buffers, queues, concurrency, and runtimes are bounded and
  configurable; see [Configuration](#configuration).

## Development

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test          # unit + CLI + lab + adversarial suites, local targets only
cargo bench         # local lab only
cargo audit         # needs cargo-audit; clean at release
```

CI runs fmt, clippy, tests, and a debug build on Ubuntu and Windows for
every push and pull request.

## License

MIT — see [LICENSE](LICENSE).
