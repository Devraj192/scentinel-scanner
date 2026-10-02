use sentinelscan_core::detection::service::{sniff_version, Evidence};
use sentinelscan_core::os::fingerprint;
use sentinelscan_core::results::model::{
    host_table, os_lines, service_table, terminal_table, to_csv, Banner, HostResult, HostStatus,
    PortResult, PortState, Scan,
};
use sentinelscan_core::safety::ports::parse_ports;
use sentinelscan_core::safety::scope::{parse_single_target, parse_targets};
use sentinelscan_core::storage::compare;

/// Deterministic xorshift64: reproducible adversarial inputs, no new crates.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }

    fn byte(&mut self) -> u8 {
        // Mix controls, text, protocol words, and high bytes.
        const POOL: &[u8] = b"\x00\x01\x07\x08\x1b\r\n\t ,.-_/:;\"'()[]{}SSHHTTP220GETPOSTTTLDNSvsFTPdUbuntu\xff\xfe\x80";
        POOL[self.below(POOL.len())]
    }

    fn bytes(&mut self, max: usize) -> Vec<u8> {
        let len = self.below(max);
        (0..len).map(|_| self.byte()).collect()
    }

    fn string(&mut self, max: usize) -> String {
        String::from_utf8_lossy(&self.bytes(max)).into_owned()
    }

    /// Mutate a valid seed: insert, delete, or replace bytes.
    fn mutate(&mut self, seed: &[u8]) -> Vec<u8> {
        let mut out = seed.to_vec();
        for _ in 0..3 {
            match self.below(3) {
                0 => out.insert(self.below(out.len() + 1), self.byte()),
                1 => {
                    if !out.is_empty() {
                        out.remove(self.below(out.len()));
                    }
                }
                _ => {
                    if !out.is_empty() {
                        let index = self.below(out.len());
                        let byte = self.byte();
                        out[index] = byte;
                    }
                }
            }
        }
        out
    }
}

fn has_bare_control(text: &str) -> bool {
    text.chars()
        .any(|c| c.is_control() && c != '\n' && c != '\t')
}

#[test]
fn parsers_reject_garbage_with_typed_errors() {
    use sentinelscan_core::Error;

    let mut rng = Rng(0xC0FFEE);
    let seeds: &[&[u8]] = &[
        b"127.0.0.1",
        b"::1",
        b"10.0.0.0/8",
        b"example.com",
        b"999.1.1.1",
        b"",
        b" ",
        b"1-1024",
        b"80,443",
        b"quick",
    ];
    let mut accepted_targets = 0;
    let mut rejected_targets = 0;
    let mut accepted_ports = 0;
    let mut rejected_ports = 0;
    for _ in 0..2000 {
        let seed = seeds[rng.below(seeds.len())];
        // The raw seed exercises the valid side; the mutation the hostile one.
        let candidates = [
            String::from_utf8_lossy(seed).into_owned(),
            String::from_utf8_lossy(&rng.mutate(seed)).into_owned(),
        ];
        for text in candidates {
            match parse_targets(std::slice::from_ref(&text), true, 256) {
                Ok(targets) => {
                    accepted_targets += 1;
                    // Accepted targets are well-formed: they display and re-parse.
                    for target in &targets {
                        let shown = target.to_string();
                        assert!(!shown.is_empty());
                        assert!(
                            parse_single_target(&shown, true).is_ok(),
                            "accepted target must re-parse: {shown}"
                        );
                    }
                }
                Err(e) => {
                    rejected_targets += 1;
                    // Rejections name the problem; scope violations never arise
                    // from parsing alone.
                    assert!(
                        matches!(e, Error::InvalidTarget { .. } | Error::LimitExceeded(_)),
                        "unexpected rejection kind: {e}"
                    );
                }
            }

            match parse_ports(&text, 1024) {
                Ok(ports) => {
                    accepted_ports += 1;
                    assert!(!ports.is_empty());
                    assert!(
                        ports.windows(2).all(|pair| pair[0] < pair[1]),
                        "sorted, deduped"
                    );
                    assert!(ports.iter().all(|port| (1..=65535).contains(port)));
                }
                Err(e) => {
                    rejected_ports += 1;
                    assert!(
                        matches!(e, Error::InvalidPort { .. } | Error::LimitExceeded(_)),
                        "unexpected rejection kind: {e}"
                    );
                }
            }
        }
    }
    // The seed mix must exercise both sides; otherwise the test proves nothing.
    assert!(accepted_targets > 100, "seeds should include valid targets");
    assert!(rejected_targets > 100, "mutations should break targets");
    assert!(
        accepted_ports > 100,
        "seeds should include valid port specs"
    );
    assert!(rejected_ports > 100, "mutations should break port specs");
}

#[test]
fn detectors_never_panic_and_stay_in_bounds() {
    let mut rng = Rng(0xDE7EC7);
    let detectors = sentinelscan_core::detection::all();
    for _ in 0..2000 {
        let banner = if rng.below(2) == 0 {
            rng.bytes(256)
        } else {
            rng.mutate(b"SSH-2.0-OpenSSH_9.3\r\n220 mail ESMTP X\r\nHTTP/1.1 200 OK\r\n")
        };
        for detector in &detectors {
            if let Some(detection) = detector.match_banner(&banner, 80) {
                assert!(
                    (0.0..=1.0).contains(&detection.confidence),
                    "confidence clamped"
                );
                assert!(!detection.service.is_empty());
                for evidence in &detection.evidence {
                    assert!(!has_bare_control(&evidence.detail), "evidence sanitized");
                }
                if let Some(version) = &detection.version {
                    assert!(!has_bare_control(version), "version sanitized");
                }
            }
        }
        let _ = sniff_version(&String::from_utf8_lossy(&banner));
    }
}

fn hostile_scan(rng: &mut Rng) -> Scan {
    // Production addresses, services, and versions never contain newlines
    // (IP literals, validated hostnames, sanitized detector output), so the
    // fixtures mirror that while staying hostile everywhere else.
    let clean = |text: String| text.replace(['\n', '\r'], "");
    let mut scan = Scan::start("01HOSTILE".to_owned(), vec![rng.string(32)]);
    for _ in 0..3 {
        let banner_bytes = rng.bytes(512);
        let banner_text = String::from_utf8_lossy(&banner_bytes).into_owned();
        scan.hosts.push(HostResult {
            address: clean(rng.string(48)),
            status: HostStatus::Up,
            latency_ms: 1,
            ports: vec![PortResult {
                port: rng.below(65536) as u16,
                protocol: clean(rng.string(16)),
                state: PortState::Open,
                reason: clean(rng.string(16)),
                latency_ms: 1,
                service: Some(clean(rng.string(32))),
                version: Some(clean(rng.string(32))),
                confidence: Some(0.5),
                evidence: vec![Evidence::observation(&banner_text)],
                banner: Some(Banner {
                    text: banner_text,
                    encoding: "utf8".to_owned(),
                    truncated: false,
                    raw: banner_bytes,
                }),
            }],
            os: None,
        });
    }
    scan
}

#[test]
fn csv_quotes_embedded_newlines() {
    let mut scan = Scan::start("01NL".to_owned(), vec![]);
    scan.hosts.push(HostResult {
        address: "127.0.0.1".to_owned(),
        status: HostStatus::Up,
        latency_ms: 1,
        ports: vec![PortResult {
            port: 80,
            protocol: "tcp".to_owned(),
            state: PortState::Open,
            reason: "handshake".to_owned(),
            latency_ms: 1,
            service: Some("a\nb".to_owned()),
            version: None,
            confidence: None,
            evidence: Vec::new(),
            banner: None,
        }],
        os: None,
    });
    assert!(to_csv(&scan).contains("\"a\nb\""));
}

/// Count CSV fields respecting RFC 4180 quoting (`""` escapes).
fn csv_fields(line: &str) -> usize {
    let mut count = 1;
    let mut in_quotes = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' if in_quotes => {
                if chars.peek() == Some(&'"') {
                    chars.next();
                } else {
                    in_quotes = false;
                }
            }
            '"' => in_quotes = true,
            ',' if !in_quotes => count += 1,
            _ => {}
        }
    }
    count
}

#[test]
fn renderers_never_emit_bare_controls() {
    let mut rng = Rng(0x2E4DE2);
    for _ in 0..500 {
        let scan = hostile_scan(&mut rng);
        // Service/version/evidence paths sanitize at construction, but the
        // tables must hold regardless of what reaches them.
        assert!(!has_bare_control(&terminal_table(&scan)));
        assert!(!has_bare_control(&service_table(&scan)));
        assert!(!has_bare_control(&host_table(&scan.hosts)));
        assert!(!has_bare_control(&os_lines(&scan)));
        // CSV rows stay rectangular: every row has the header's field count.
        let csv = to_csv(&scan);
        let header_fields = csv_fields(csv.lines().next().unwrap_or(""));
        for line in csv.lines() {
            assert_eq!(csv_fields(line), header_fields, "{line:?}");
        }
    }
}

#[test]
fn os_fingerprint_never_panics_and_never_overclaims() {
    let mut rng = Rng(0x05F9);
    for _ in 0..2000 {
        let scan = hostile_scan(&mut rng);
        let ports: Vec<PortResult> = scan
            .hosts
            .iter()
            .flat_map(|host| host.ports.clone())
            .collect();
        let guess = fingerprint(&ports);
        assert!(guess.confidence <= 0.65, "banner hints stay weak");
        assert!(!has_bare_control(&guess.family));
        if guess.version.is_some() {
            assert_ne!(guess.family, "Unknown", "versions need a family claim");
        }
    }
}

#[test]
fn compare_never_panics() {
    let mut rng = Rng(0xC0BA1);
    for _ in 0..200 {
        let older = hostile_scan(&mut rng);
        let newer = hostile_scan(&mut rng);
        let diff = compare(&older, &newer);
        let _ = (diff.added.len(), diff.removed.len(), diff.changed.len());
    }
}
