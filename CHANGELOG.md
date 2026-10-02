# Changelog

## 2.0.0 — V2 release

Workspace split (`sentinelscan-core` + `sentinelscan`), typed scan event
stream, XDG paths with v1 backup-migration, Unix fd clamp, SIGTERM handling,
`doctor`, plain-language CLI (wizard, `explain`/`init`/`completions`/`man`),
ratatui TUI, musl static builds, `.deb`/`.rpm`, install script, container
image, crates.io publishing, license MIT OR Apache-2.0. See MIGRATING.md.

ratatui terminal UI sharing the engine event stream: home, guided new scan,
live progress with pause/cancel, results with filter/sort/search, detail with
explanations, history with delete/export, compare, help. Pausable rate
limiter in core, `delete_scan` in storage, no-socket CI guard for UI code.

Guided scan wizard, `explain`/`init`/`completions`/`man`, examples in every
help text, end-of-scan summaries, what/why/fix error hints, first-run
authorized-use acknowledgement. Non-interactive behavior unchanged.

Unix fd-limit clamp with warning, SIGTERM handling, `doctor` subcommand,
`--version` with commit and target, musl static-build CI plus a five-distro
container smoke matrix. No behavior change to scanning itself.

Workspace split (`sentinelscan-core` library + `sentinelscan` binary),
typed scan event stream with the CLI as consumer, `schema_version: 2` in
JSON, XDG data/config paths with fallback, v1 history relocation with
timestamped backup. No behavior change: v1 lab assertions hold unchanged.

Review-driven hardening: parsers assert typed rejections and re-parse
round-trips instead of a tautology, proptest properties plus a blank-service
guard in `Detection::new`, batched SQLite transactions with busy timeout,
documented detection traffic budget and operations notes.

## 1.0.0 — Release

First stable release. Same code as 0.5.0 plus version bump, README, and MIT
LICENSE. All PRD phases complete; definition of done satisfied.

OS fingerprinting from service banners with evidence and capped confidence
(`Unknown` on thin signals), public library API with docs, criterion
benchmarks plus lab stats, adversarial hardening tests, `cargo audit` clean,
CI workflow, README with configuration reference, release build.

## 0.4.0 — Phase 4

SQLite history with migrations, `history` and `compare` subcommands,
Quick/Standard/Custom profiles with `[profiles.*]` config overrides,
resumable scans via `scan --resume`, progress persisted per probe and per
detection, owner-only history permissions on Unix.

## 0.3.0 — Phase 3

Pluggable service detection (SSH, FTP, SMTP, HTTP, HTTPS, DNS, Generic) with
evidence and confidence, bounded banner grabbing with sanitization, staged
pipeline over open ports only, CSV output, `services` subcommand, Standard
profile detection enabled.

## 0.2.0 — Phase 2

Async TCP connect engine through `ScopeGuard` with open/closed/filtered/unknown
classification and per-port reasons. Semaphore concurrency cap plus independent
smooth rate limiter, connect/probe/overall timeouts, Ctrl-C partial results,
TCP host discovery, canonical result model with terminal and JSON output,
`hosts` and `ports` subcommands.

## 0.1.0 — Phase 1

Foundation with target/port parsing, TOML config with conservative defaults,
`ScopeGuard`, scope summary plus confirmation prompt, `tracing` with ULID
`scan_id`. No traffic sent.
