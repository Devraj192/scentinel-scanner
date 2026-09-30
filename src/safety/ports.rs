use crate::errors::Error;
use crate::safety::limits::enforce_port_count;

const MAX_PORT: u32 = 65535;

/// Ports for the `quick` named profile.
pub fn quick_ports() -> Vec<u16> {
    vec![80, 443]
}

/// Ports for the `standard` named profile.
pub fn standard_ports() -> Vec<u16> {
    vec![22, 80, 443, 8080, 8443]
}

/// Ports for the `full` named profile (1-1024).
pub fn full_ports() -> Vec<u16> {
    (1u16..=1024).collect()
}

fn parse_one_port(part: &str, spec: &str) -> Result<u16, Error> {
    let value: u32 = part
        .parse()
        .map_err(|_| Error::port(spec, "port must be a number 1-65535"))?;
    if value == 0 || value > MAX_PORT {
        return Err(Error::port(spec, "port must be a number 1-65535"));
    }
    Ok(value as u16)
}

/// Parse a port spec: single (`22`), list (`80,443,8080`), range (`1-1024`),
/// mixed (`22,80-85,443`), or named profile (`quick`, `standard`, `full`).
pub fn parse_ports(spec: &str, max_ports: usize) -> Result<Vec<u16>, Error> {
    let trimmed = spec.trim();
    if trimmed.is_empty() {
        return Err(Error::port(spec, "empty port spec"));
    }
    let lowered = trimmed.to_lowercase();
    if lowered == "quick" {
        let ports = quick_ports();
        enforce_port_count(ports.len(), max_ports)?;
        return Ok(ports);
    }
    if lowered == "standard" {
        let ports = standard_ports();
        enforce_port_count(ports.len(), max_ports)?;
        return Ok(ports);
    }
    if lowered == "full" {
        let ports = full_ports();
        enforce_port_count(ports.len(), max_ports)?;
        return Ok(ports);
    }

    let mut ports: Vec<u16> = Vec::new();
    for part in trimmed.split(',') {
        let part = part.trim();
        if part.is_empty() {
            return Err(Error::port(spec, "empty entry in port list"));
        }
        if let Some((start_s, end_s)) = part.split_once('-') {
            let start = parse_one_port(start_s.trim(), spec)?;
            let end = parse_one_port(end_s.trim(), spec)?;
            if start > end {
                return Err(Error::port(spec, "range start exceeds range end"));
            }
            // Bound the loop itself; a hostile 1-65535 with a small cap
            // must fail fast instead of allocating.
            let range_len = (end as usize)
                .saturating_sub(start as usize)
                .saturating_add(1);
            enforce_port_count(ports.len().saturating_add(range_len), max_ports)?;
            ports.extend(start..=end);
        } else {
            ports.push(parse_one_port(part, spec)?);
        }
    }
    ports.sort_unstable();
    ports.dedup();
    enforce_port_count(ports.len(), max_ports)?;
    if ports.is_empty() {
        return Err(Error::port(spec, "no ports parsed"));
    }
    Ok(ports)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_single_list_range() {
        assert_eq!(parse_ports("22", 1024).expect("single"), vec![22]);
        assert_eq!(
            parse_ports("80,443,8080", 1024).expect("list"),
            vec![80, 443, 8080]
        );
        assert_eq!(parse_ports("1-4", 1024).expect("range"), vec![1, 2, 3, 4]);
    }

    #[test]
    fn parses_named_profiles() {
        assert_eq!(parse_ports("quick", 1024).expect("quick"), vec![80, 443]);
        assert!(parse_ports("standard", 1024)
            .expect("standard")
            .contains(&22));
    }

    #[test]
    fn rejects_bad_ports() {
        assert!(parse_ports("0", 1024).is_err());
        assert!(parse_ports("65536", 1024).is_err());
        assert!(parse_ports("10-5", 1024).is_err());
        assert!(parse_ports("", 1024).is_err());
        assert!(parse_ports("80,,443", 1024).is_err());
        assert!(parse_ports("abc", 1024).is_err());
    }

    #[test]
    fn enforces_max_ports() {
        assert!(parse_ports("1-1025", 1024).is_err());
    }
}
