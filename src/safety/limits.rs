use crate::errors::Error;

/// Enforce configured caps before allocating or scanning.
pub fn enforce_host_count(count: usize, max_hosts: usize) -> Result<(), Error> {
    if count > max_hosts {
        return Err(Error::LimitExceeded(format!(
            "host count {count} exceeds max_hosts {max_hosts}"
        )));
    }
    Ok(())
}

/// Enforce configured caps before allocating or scanning.
pub fn enforce_port_count(count: usize, max_ports: usize) -> Result<(), Error> {
    if count > max_ports {
        return Err(Error::LimitExceeded(format!(
            "port count {count} exceeds max_ports {max_ports}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_over_limit() {
        assert!(enforce_host_count(257, 256).is_err());
        assert!(enforce_port_count(1025, 1024).is_err());
    }

    #[test]
    fn accepts_at_limit() {
        assert!(enforce_host_count(256, 256).is_ok());
        assert!(enforce_port_count(1024, 1024).is_ok());
    }
}
