# Security

## Scope

SentinelScan is an authorized-use network scanner. It contains no
exploitation, credential guessing, brute forcing, denial-of-service,
evasion, or destructive protocol features, and accepts no such contributions
(see CONTRIBUTING.md).

## Reporting a vulnerability

Email the maintainer (see `Cargo.toml`) with:

1. A description of the issue and its impact.
2. Steps to reproduce against `127.0.0.1` only — never against third-party systems.
3. The version (`sentinelscan --version`) and platform.

Do not open a public issue for a suspected vulnerability. Expect an initial
response within 7 days. Fixes ship as patch releases; the advisory is
published after a fix is available.

## What is scanned, and what leaves the machine

- The scanner connects only to user-declared scope, enforced by `ScopeGuard`;
  every socket operation passes through it.
- Hostname targets resolve once via the system resolver; nothing else causes
  DNS traffic.
- There is no telemetry. Update checks do not exist in this release, so a
  network capture of any run shows outbound traffic only to scan targets
  (plus the resolver you configured).
- Scan history is a local SQLite file with owner-only permissions on Unix.
  Delete it with `rm` on the history directory; `compare`/`history` never
  transmit anything.

## Hardening posture

- All network-derived bytes are length-capped before allocation and
  sanitized before display or storage.
- Terminal output never contains control or escape sequences (tested,
  including a hostile-banner fixture).
- Dependencies are gated by `cargo audit` and `cargo deny` in CI.
