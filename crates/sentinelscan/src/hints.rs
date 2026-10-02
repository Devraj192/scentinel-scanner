/// Every error says what went wrong, why it likely happened, and one command
/// to fix it. The table is keyed on error-text fragments; the unit test below
/// lists every branch so a new error path cannot slip in unexplained.
pub fn hint_for(error: &anyhow::Error) -> Option<&'static str> {
    let text = format!("{error:#}");
    // Order matters: specific fragments before general ones.
    for (fragment, fix) in [
        (
            "hostname given but hostnames are disabled",
            "hostnames need --allow-hostnames: sentinelscan scan example.com --allow-hostnames --ports 80,443 --yes",
        ),
        (
            "invalid target",
            "targets look like 127.0.0.1, ::1, 10.0.0.0/24, or a hostname with --allow-hostnames: sentinelscan scan 127.0.0.1 --ports 22,80 --yes",
        ),
        (
            "invalid port",
            "ports look like 22, 80,443, 1-1024, or quick|standard|full: sentinelscan scan 127.0.0.1 --ports 1-1024 --yes",
        ),
        (
            "exceeds max_",
            "lower the request (--ports, --concurrency, --rate) or raise the cap in config: sentinelscan config",
        ),
        (
            "no targets given",
            "pass a target (sentinelscan scan 127.0.0.1 --ports 80 --yes) or run interactively on a terminal for guided setup",
        ),
        (
            "cannot be combined with targets",
            "drop targets and --ports; resume reuses the stored scope: sentinelscan scan --resume <scan_id> --yes",
        ),
        (
            "only interrupted scans can resume",
            "check which scans are resumable: sentinelscan history",
        ),
        (
            "unknown scan id",
            "list stored scans first: sentinelscan history",
        ),
        (
            "unknown output",
            "use --output terminal, json, or csv",
        ),
        (
            "unknown profile",
            "use --profile quick, standard, or custom",
        ),
        (
            "scan duration exceeded",
            "raise max_scan_duration_secs in config, or resume what was saved: sentinelscan scan --resume <scan_id> --yes",
        ),
        (
            "cannot open",
            "check the path and directory permissions, or pick another file with --db",
        ),
        (
            "cannot read",
            "check the config path, or print defaults: sentinelscan config",
        ),
        (
            "doctor found failing checks",
            "fixes are printed above each failing check",
        ),
        (
            "config file already exists",
            "edit it in place, or re-run with --force to overwrite",
        ),
        (
            "declined",
            "scanning requires agreeing to test only authorized targets",
        ),
        (
            "first run requires acknowledgement",
            "re-run with --yes after reading the authorized-use notice",
        ),
    ] {
        if text.contains(fragment) {
            return Some(fix);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_listed_branch_fires() {
        let cases = [
            (
                "hostname given but hostnames are disabled",
                "--allow-hostnames",
            ),
            ("invalid target 'x'", "127.0.0.1 --ports"),
            ("invalid port spec 'x'", "--ports 1-1024"),
            ("port count 9 exceeds max_ports", "--concurrency"),
            ("host count 9 exceeds max_hosts", "sentinelscan config"),
            ("no targets given", "guided setup"),
            (
                "--resume cannot be combined with targets",
                "--resume <scan_id>",
            ),
            ("only interrupted scans can resume", "sentinelscan history"),
            ("unknown scan id 'x'", "sentinelscan history"),
            ("unknown output 'x'", "terminal, json"),
            ("unknown profile 'x'", "quick, standard"),
            ("scan duration exceeded", "--resume <scan_id>"),
            ("cannot open /tmp/x", "--db"),
            ("cannot read x", "sentinelscan config"),
            ("doctor found failing checks", "printed above"),
            ("config file already exists", "--force"),
            ("declined", "authorized targets"),
            ("first run requires acknowledgement", "--yes"),
        ];
        for (message, fix_fragment) in cases {
            let error = anyhow::anyhow!("{message}");
            let fix = hint_for(&error).expect("every branch explained");
            assert!(fix.contains(fix_fragment), "{message} -> {fix}");
        }
    }

    #[test]
    fn unknown_errors_stay_hintless() {
        assert_eq!(hint_for(&anyhow::anyhow!("mystery failure")), None);
    }
}
