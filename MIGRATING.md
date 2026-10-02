# Migrating to v2

v2 keeps every v1 safety guarantee and every v1 result. What changed:

## Layout

The single crate became a workspace: `sentinelscan-core` (engine library)
plus `sentinelscan` (binary). Library users change one import line:

```rust
// v1
use sentinelscan::{Config, Storage};
// v2
use sentinelscan_core::{Config, Storage};
```

The CLI binary name, flags, and defaults are unchanged.

## History and config locations

- History moved from `.sentinelscan/history.db` in the working directory to
  the XDG data directory (`~/.local/share/sentinelscan/history.db`). The
  first v2 run copies the v1 file there and keeps a timestamped
  `.bak` backup beside the original. `--db` overrides everything, as before.
- Config is read from `--config`, else `$XDG_CONFIG_HOME/sentinelscan/config.toml`
  when that file exists, else built-in defaults. `sentinelscan init` writes it.
- History file permissions are unchanged (owner-only on Unix).

## JSON

One additive field: `meta.schema_version` (currently `2`). Every v1 field
remains with the same meaning. Payloads without the field still parse.

## License

`MIT` became `MIT OR Apache-2.0` (see `LICENSE-MIT`, `LICENSE-APACHE`).
Use under either; no code changes required.

## Defaults

Conservative defaults are unchanged, including the scope confirmation step.
`--output json` output is unchanged apart from the additive `schema_version`.
