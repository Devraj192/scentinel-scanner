# Contributing

## Ground rules

1. **Authorized use only.** No exploitation, credential guessing, brute
   forcing, denial of service, evasion, or destructive protocol features.
   Such contributions are refused with an explanation.
2. **Safety first.** Every socket operation goes through `ScopeGuard`,
   with no bypass path. All buffers, queues, concurrency, and runtimes
   stay bounded. Timeouts are never `closed`; `unknown` is always valid.
3. **One phase, one commit.** Larger work is split per the PRD phase list;
   each commit passes the full gate suite on its own.
4. **No AI slop.** No stubs, no `todo!()`, no `unwrap()` outside tests, no
   `#[allow]` to silence lints, no drive-by refactors, no marketing language.

## Workflow

```sh
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Target only `127.0.0.1`, `::1`, or lab fixtures you own. Never scan external
hosts in tests, and never hardcode public IPs or domains.

New detectors go in `crates/sentinelscan-core/src/protocols/` plus one line
in the registry (`detection::all`), with fixture tests proving service,
version-or-unknown, confidence, and evidence. New UI code goes in
`crates/sentinelscan/src/tui/` and must not open sockets (CI greps for it).

## Licensing

Contributions are accepted under MIT OR Apache-2.0, matching `LICENSE-MIT`
and `LICENSE-APACHE`.
