/// Checks if a host is valid or if it is a valid IP address.
pub fn is_valid_host(host: &str) -> bool {
    host.parse::<std::net::SocketAddr>().is_ok()
        || host.parse::<std::net::IpAddr>().is_ok()
        || url::Host::parse(host).is_ok()
}

/// Represents a parsed authority.
#[derive(Debug, Clone)]
pub struct Authority {
    pub host: Host,
    pub port: u16,
}

/// Represents a parsed host.
#[derive(Debug, Clone)]
pub enum Host {
    Domain(String),
    Ip(std::net::IpAddr),
}

#[non_exhaustive]
pub enum AuthorityError {
    InvalidHost,
}

impl Authority {
    /// Parses an authority from a string.
    pub fn parse(authority: &str) -> Result<Self, AuthorityError> {
        if let Ok(addr) = authority.parse::<std::net::SocketAddr>() {
            return Ok(Self {
                host: Host::Ip(addr.ip()),
                port: addr.port(),
            });
        }

        if let Ok(ip) = authority.parse::<std::net::IpAddr>() {
            return Ok(Self {
                host: Host::Ip(ip),
                port: 0,
            });
        }

        let host = url::Host::parse(authority).map_err(|_| AuthorityError::InvalidHost)?;

        Ok(Self {
            host: Host::Domain(host.to_string()),
            port: 0,
        })
    }
}
