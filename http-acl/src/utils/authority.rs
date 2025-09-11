//! Utilities for parsing authorities.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

/// Checks if a host is valid or if it is a valid IP address.
pub fn is_valid_host(host: &str) -> bool {
    host.parse::<std::net::SocketAddr>().is_ok()
        || host.parse::<IpAddr>().is_ok()
        || url::Host::parse(host).is_ok()
}

/// Represents a parsed authority.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Authority {
    /// The host, which can be a domain or an IP address.
    pub host: Host,
    /// The port.
    pub port: u16,
}

impl std::fmt::Display for Authority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.port == 0 {
            write!(f, "{}", self.host)
        } else {
            write!(f, "{}:{}", self.host, self.port)
        }
    }
}

impl From<SocketAddr> for Authority {
    fn from(value: SocketAddr) -> Self {
        Authority {
            host: match value {
                SocketAddr::V4(addr) => Host::Ip(IpAddr::V4(*addr.ip())),
                SocketAddr::V6(addr) => Host::Ip(IpAddr::V6(*addr.ip())),
            },
            port: value.port(),
        }
    }
}

impl From<SocketAddrV4> for Authority {
    fn from(value: SocketAddrV4) -> Self {
        Authority {
            host: Host::Ip(IpAddr::V4(*value.ip())),
            port: value.port(),
        }
    }
}

impl From<SocketAddrV6> for Authority {
    fn from(value: SocketAddrV6) -> Self {
        Authority {
            host: Host::Ip(IpAddr::V6(*value.ip())),
            port: value.port(),
        }
    }
}

impl From<(String, u16)> for Authority {
    fn from(value: (String, u16)) -> Self {
        Authority {
            host: Host::Domain(value.0),
            port: value.1,
        }
    }
}

impl From<(&str, u16)> for Authority {
    fn from(value: (&str, u16)) -> Self {
        Authority {
            host: Host::Domain(value.0.to_string()),
            port: value.1,
        }
    }
}

impl From<(IpAddr, u16)> for Authority {
    fn from(value: (IpAddr, u16)) -> Self {
        Authority {
            host: Host::Ip(value.0),
            port: value.1,
        }
    }
}

impl From<(Ipv4Addr, u16)> for Authority {
    fn from(value: (Ipv4Addr, u16)) -> Self {
        Authority {
            host: Host::Ip(IpAddr::V4(value.0)),
            port: value.1,
        }
    }
}

impl From<String> for Authority {
    fn from(value: String) -> Self {
        Authority {
            host: Host::Domain(value),
            port: 0,
        }
    }
}

impl From<&str> for Authority {
    fn from(value: &str) -> Self {
        Authority {
            host: Host::Domain(value.to_string()),
            port: 0,
        }
    }
}

impl From<IpAddr> for Authority {
    fn from(value: IpAddr) -> Self {
        Authority {
            host: Host::Ip(value),
            port: 0,
        }
    }
}

impl From<Ipv4Addr> for Authority {
    fn from(value: Ipv4Addr) -> Self {
        Authority {
            host: Host::Ip(IpAddr::V4(value)),
            port: 0,
        }
    }
}

impl From<Ipv6Addr> for Authority {
    fn from(value: Ipv6Addr) -> Self {
        Authority {
            host: Host::Ip(IpAddr::V6(value)),
            port: 0,
        }
    }
}

/// Represents a parsed host.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Host {
    /// A domain.
    Domain(String),
    /// An IP address.
    Ip(IpAddr),
}

impl Host {
    /// Returns true if the host is an IP address.
    pub fn is_ip(&self) -> bool {
        matches!(self, Host::Ip(_))
    }

    /// Returns true if the host is a domain.
    pub fn is_domain(&self) -> bool {
        matches!(self, Host::Domain(_))
    }
}

impl std::fmt::Display for Host {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Host::Domain(domain) => write!(f, "{domain}"),
            Host::Ip(ip) => match ip {
                IpAddr::V4(ip) => write!(f, "{ip}"),
                IpAddr::V6(ip) => write!(f, "[{ip}]"),
            },
        }
    }
}

impl From<String> for Host {
    fn from(value: String) -> Self {
        Host::Domain(value)
    }
}

impl From<&str> for Host {
    fn from(value: &str) -> Self {
        Host::Domain(value.to_string())
    }
}

impl From<IpAddr> for Host {
    fn from(value: IpAddr) -> Self {
        Host::Ip(value)
    }
}

impl From<Ipv4Addr> for Host {
    fn from(value: Ipv4Addr) -> Self {
        Host::Ip(IpAddr::V4(value))
    }
}

impl From<Ipv6Addr> for Host {
    fn from(value: Ipv6Addr) -> Self {
        Host::Ip(IpAddr::V6(value))
    }
}

#[non_exhaustive]
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
/// An error that can occur when parsing an authority.
pub enum AuthorityError {
    /// The host is invalid.
    InvalidHost,
}

impl std::fmt::Display for AuthorityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthorityError::InvalidHost => write!(f, "invalid host"),
        }
    }
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

        if let Ok(ip) = authority.parse::<IpAddr>() {
            return Ok(Self {
                host: Host::Ip(ip),
                port: 0,
            });
        }

        match url::Host::parse(authority) {
            Ok(url::Host::Domain(domain)) => Ok(Self {
                host: Host::Domain(domain),
                port: 0,
            }),
            Ok(url::Host::Ipv4(ip)) => Ok(Self {
                host: Host::Ip(ip.into()),
                port: 0,
            }),
            Ok(url::Host::Ipv6(ip)) => Ok(Self {
                host: Host::Ip(ip.into()),
                port: 0,
            }),
            Err(_) => {
                if let Some((domain, port)) = authority.split_once(':')
                    && let Ok(port) = port.parse::<u16>()
                {
                    url::Host::parse(domain).map_err(|_| AuthorityError::InvalidHost)?;

                    return Ok(Self {
                        host: Host::Domain(domain.to_string()),
                        port,
                    });
                }

                Err(AuthorityError::InvalidHost)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_is_valid_host() {
        assert!(is_valid_host("localhost"));
        assert!(is_valid_host("example.com"));
        assert!(is_valid_host("127.0.0.1"));
        assert!(is_valid_host("::1"));
        assert!(is_valid_host("[::1]"));
    }

    #[test]
    fn test_authority_parse() {
        assert_eq!(
            Authority::parse("localhost").unwrap(),
            Authority {
                host: Host::Domain("localhost".to_string()),
                port: 0
            }
        );
        assert_eq!(
            Authority::parse("localhost:5000").unwrap(),
            Authority {
                host: Host::Domain("localhost".to_string()),
                port: 5000
            }
        );
        assert_eq!(
            Authority::parse("example.com").unwrap(),
            Authority {
                host: Host::Domain("example.com".to_string()),
                port: 0
            }
        );
        assert_eq!(
            Authority::parse("example.com:443").unwrap(),
            Authority {
                host: Host::Domain("example.com".to_string()),
                port: 443
            }
        );
        assert_eq!(
            Authority::parse("127.0.0.1").unwrap(),
            Authority {
                host: Host::Ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
                port: 0
            }
        );
        assert_eq!(
            Authority::parse("127.0.0.1:80").unwrap(),
            Authority {
                host: Host::Ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
                port: 80
            }
        );
        assert_eq!(
            Authority::parse("::1").unwrap(),
            Authority {
                host: Host::Ip(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1))),
                port: 0
            }
        );
        assert_eq!(
            Authority::parse("[::1]").unwrap(),
            Authority {
                host: Host::Ip(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1))),
                port: 0
            }
        );
        assert_eq!(
            Authority::parse("[::1]:80").unwrap(),
            Authority {
                host: Host::Ip(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1))),
                port: 80
            }
        );
    }
}
