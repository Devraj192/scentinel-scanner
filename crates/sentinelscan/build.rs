fn main() {
    let commit = std::process::Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|stdout| stdout.trim().to_owned())
        .filter(|commit| !commit.is_empty())
        .unwrap_or_else(|| "unknown".to_owned());
    let target = std::env::var("TARGET").unwrap_or_else(|_| "unknown".to_owned());
    println!(
        "cargo:rustc-env=SENTINELSCAN_BUILD={} ({}, {})",
        env!("CARGO_PKG_VERSION"),
        commit,
        target
    );
    println!("cargo:rerun-if-changed=.git/HEAD");
}
