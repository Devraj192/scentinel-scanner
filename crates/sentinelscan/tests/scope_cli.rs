use std::io::Write as _;
use std::process::{Command, Stdio};

fn binary() -> String {
    env!("CARGO_BIN_EXE_sentinelscan").to_owned()
}

#[test]
fn scan_prints_scope_then_results_table() {
    let db = std::env::temp_dir().join(format!("sentinelscan-scope-{}.db", std::process::id()));
    let output = Command::new(binary())
        .args([
            "scan",
            "127.0.0.1",
            "--ports",
            "80",
            "--yes",
            "--skip-host-discovery",
            "--db",
            db.to_str().expect("utf8"),
        ])
        .output()
        .expect("run binary");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Authorized use only"), "{stdout}");
    assert!(stdout.contains("HOST"), "{stdout}");
    assert!(stdout.contains("127.0.0.1"), "{stdout}");
}

#[test]
fn scan_aborts_on_no() {
    let mut child = Command::new(binary())
        .args(["scan", "127.0.0.1", "--ports", "80"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn binary");
    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(b"n\n")
        .expect("answer no");
    let output = child.wait_with_output().expect("wait");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Aborted"), "{stdout}");
}

#[test]
fn scan_rejects_malformed_target() {
    let output = Command::new(binary())
        .args(["scan", "999.999.0.1", "--ports", "80", "--yes"])
        .output()
        .expect("run binary");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stderr.contains("invalid target") || stdout.contains("invalid target"),
        "stderr: {stderr} stdout: {stdout}"
    );
}

#[test]
fn doctor_reports_without_changing_anything() {
    let output = Command::new(binary())
        .args(["doctor"])
        .output()
        .expect("run binary");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("CHECK"), "{stdout}");
    assert!(stdout.contains("dns"), "{stdout}");
}

#[test]
fn explain_states_in_plain_language() {
    let output = Command::new(binary())
        .args(["explain", "filtered"])
        .output()
        .expect("run binary");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("firewall"), "{stdout}");
    let output = Command::new(binary())
        .args(["explain", "banana"])
        .output()
        .expect("run binary");
    assert!(!output.status.success());
}

#[test]
fn completions_and_man_render() {
    let output = Command::new(binary())
        .args(["completions", "bash"])
        .output()
        .expect("run binary");
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("sentinelscan"));
    let output = Command::new(binary())
        .args(["man"])
        .output()
        .expect("run binary");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains(".TH sentinelscan"), "{stdout:.200}");
}

#[test]
fn scan_enforces_max_ports() {
    let output = Command::new(binary())
        .args(["scan", "127.0.0.1", "--ports", "1-1025", "--yes"])
        .output()
        .expect("run binary");
    assert!(!output.status.success());
}
