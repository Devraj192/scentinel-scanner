use std::process::Command;

fn binary() -> String {
    env!("CARGO_BIN_EXE_sentinelscan").to_owned()
}

#[test]
fn scan_prints_scope_and_sends_no_traffic() {
    let output = Command::new(binary())
        .args(["scan", "127.0.0.1", "--ports", "80", "--yes"])
        .output()
        .expect("run binary");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Authorized use only"), "{stdout}");
    assert!(stdout.contains("no traffic"), "{stdout}");
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
fn scan_enforces_max_ports() {
    let output = Command::new(binary())
        .args(["scan", "127.0.0.1", "--ports", "1-1025", "--yes"])
        .output()
        .expect("run binary");
    assert!(!output.status.success());
}
