use proptest::prelude::*;
use sentinelscan::detection::service::{sniff_version, Detection};
use sentinelscan::results::model::sanitize;
use sentinelscan::safety::ports::parse_ports;

/// Any mix of text, controls, and high bytes.
fn hostile_text() -> impl Strategy<Value = String> {
    prop::collection::vec(0u8..=255u8, 0..64)
        .prop_map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// Sanitizing twice changes nothing, and the result carries no bare
    /// control characters.
    #[test]
    fn sanitize_is_idempotent_and_control_free(text in hostile_text()) {
        let once = sanitize(&text);
        prop_assert_eq!(sanitize(&once), once.as_str());
        prop_assert!(
            !once.chars().any(|c| c.is_control() && c != '\n' && c != '\t'),
            "bare control survived: {once:?}"
        );
    }

    /// Confidence is always clamped, evidence always sanitized, no matter
    /// what the detector was handed.
    #[test]
    fn detection_fields_stay_in_bounds(
        service in hostile_text(),
        version in proptest::option::of(hostile_text()),
        confidence in f32::MIN..f32::MAX,
    ) {
        let detection = Detection::new(&service, version, confidence, vec![]);
        prop_assert!((0.0..=1.0).contains(&detection.confidence));
        prop_assert!(!detection.service.is_empty());
        if let Some(version) = &detection.version {
            prop_assert!(
                !version.chars().any(|c| c.is_control() && c != '\n' && c != '\t')
            );
        }
    }

    /// Version sniffing only emits a narrow alphabet, or nothing at all.
    #[test]
    fn sniffed_versions_use_narrow_alphabet(text in hostile_text()) {
        if let Some(version) = sniff_version(&text) {
            prop_assert!(
                version
                    .chars()
                    .all(|c| c.is_alphanumeric() || ". _-".contains(c)),
                "wide alphabet: {version:?}"
            );
        }
    }

    /// Port specs built from valid parts always parse to a sorted, deduped,
    /// in-range set containing every part.
    #[test]
    fn valid_port_specs_round_trip(
        parts in prop::collection::vec(1u16..=1000u16, 1..8),
    ) {
        let spec = parts
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let parsed = parse_ports(&spec, 65535).expect("built from valid parts");
        let mut expected = parts.clone();
        expected.sort_unstable();
        expected.dedup();
        prop_assert_eq!(parsed, expected);
    }
}
