use std::net::IpAddr;

use ipnet::IpNet;

use crate::{error::AddError, utils};

#[derive(Debug)]
pub struct HttpAcl {
    allow_http: bool,
    allow_https: bool,
    allowed_hosts: Vec<String>,
    denied_hosts: Vec<String>,
    allowed_ports: Vec<u16>,
    denied_ports: Vec<u16>,
    allowed_ip_ranges: Vec<IpNet>,
    denied_ip_ranges: Vec<IpNet>,
    allow_private_ip_ranges: bool,
    allow_ip_default: bool,
}

impl std::default::Default for HttpAcl {
    fn default() -> Self {
        Self {
            allow_http: true,
            allow_https: true,
            allowed_hosts: Vec::new(),
            denied_hosts: Vec::new(),
            allowed_ports: vec![80, 443],
            denied_ports: Vec::new(),
            allowed_ip_ranges: Vec::new(),
            denied_ip_ranges: Vec::new(),
            allow_private_ip_ranges: false,
            allow_ip_default: true,
        }
    }
}

impl HttpAcl {
    /// Returns a new [`HttpAclBuilder`](HttpAclBuilder).
    pub fn builder() -> HttpAclBuilder {
        HttpAclBuilder::default()
    }

    /// Returns whether HTTP is allowed.
    pub fn allow_http(&self) -> bool {
        self.allow_http
    }

    /// Returns whether HTTPS is allowed.
    pub fn allow_https(&self) -> bool {
        self.allow_https
    }

    /// Returns whether private IP ranges are allowed.
    pub fn allow_private_ip_ranges(&self) -> bool {
        self.allow_private_ip_ranges
    }

    /// Returns whether IP addresses are allowed by default.
    pub fn allow_ip_default(&self) -> bool {
        self.allow_ip_default
    }

    /// Returns whether the host is allowed.
    pub fn is_host_allowed(&self, host: &str) -> bool {
        if self.denied_hosts.iter().any(|h| h == host) {
            false
        } else {
            self.allowed_hosts.iter().any(|h| h == host)
        }
    }

    /// Returns whether the port is allowed.
    pub fn is_port_allowed(&self, port: u16) -> bool {
        if self.denied_ports.contains(&port) {
            false
        } else {
            self.allowed_ports.contains(&port)
        }
    }

    /// Returns whether an IP is allowed.
    pub fn is_ip_allowed(&self, ip: &IpAddr) -> IpAclClassification {
        if (!utils::ip::is_global_ip(ip) || ip.is_loopback()) && !utils::ip::is_private_ip(ip) {
            if Self::is_ip_in_ranges(ip, &self.allowed_ip_ranges) {
                return IpAclClassification::AllowedUserAcl;
            } else {
                return IpAclClassification::DeniedNotGlobal;
            }
        }

        if Self::is_ip_in_ranges(ip, &self.allowed_ip_ranges) {
            IpAclClassification::AllowedUserAcl
        } else if Self::is_ip_in_ranges(ip, &self.denied_ip_ranges) {
            IpAclClassification::DeniedUserAcl
        } else if utils::ip::is_private_ip(ip) && !self.allow_private_ip_ranges {
            IpAclClassification::DeniedPrivateRange
        } else if self.allow_ip_default {
            IpAclClassification::AllowedDefault
        } else {
            IpAclClassification::DeniedDefault
        }
    }

    /// Checks if an ip is in a list of ip ranges.
    fn is_ip_in_ranges(ip: &IpAddr, ranges: &[IpNet]) -> bool {
        ranges.iter().any(|range| range.contains(ip))
    }
}

/// Represents an IP ACL Classification.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum IpAclClassification {
    /// The IP is allowed according to the allowed IP ranges.
    AllowedUserAcl,
    /// The IP is denied according to the denied IP ranges.
    DeniedUserAcl,
    /// The IP is denied because it is not global.
    DeniedNotGlobal,
    /// The IP is denied because it is in a private range.
    DeniedPrivateRange,
    /// The ip is allowed because the default is to allow if no ACL match is found.
    AllowedDefault,
    /// The ip is denied because the default is to deny if no ACL match is found.
    DeniedDefault,
}

impl std::fmt::Display for IpAclClassification {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IpAclClassification::AllowedUserAcl => {
                write!(f, "The IP is allowed according to the allowed IP ranges.")
            }
            IpAclClassification::DeniedUserAcl => {
                write!(f, "The IP is denied according to the denied IP ranges.")
            }
            IpAclClassification::DeniedNotGlobal => {
                write!(f, "The IP is denied because it is not global.")
            }
            IpAclClassification::DeniedPrivateRange => {
                write!(f, "The IP is denied because it is in a private range.")
            }
            IpAclClassification::AllowedDefault => write!(
                f,
                "The ip is allowed because the default is to allow if no ACL match is found."
            ),
            IpAclClassification::DeniedDefault => write!(
                f,
                "The ip is denied because the default is to deny if no ACL match is found."
            ),
        }
    }
}

impl IpAclClassification {
    /// Returns whether the IP is allowed.
    pub fn is_allowed(&self) -> bool {
        matches!(
            self,
            IpAclClassification::AllowedUserAcl | IpAclClassification::AllowedDefault
        )
    }

    /// Returns whether the IP is denied.
    pub fn is_denied(&self) -> bool {
        matches!(
            self,
            IpAclClassification::DeniedUserAcl
                | IpAclClassification::DeniedNotGlobal
                | IpAclClassification::DeniedPrivateRange
                | IpAclClassification::DeniedDefault
        )
    }
}

/// A builder for [`HttpAcl`](HttpAcl).
#[derive(Debug)]
pub struct HttpAclBuilder {
    allow_http: bool,
    allow_https: bool,
    allowed_hosts: Vec<String>,
    denied_hosts: Vec<String>,
    allowed_ports: Vec<u16>,
    denied_ports: Vec<u16>,
    allowed_ip_ranges: Vec<IpNet>,
    denied_ip_ranges: Vec<IpNet>,
    allow_private_ip_ranges: bool,
    allow_ip_default: bool,
}

impl std::default::Default for HttpAclBuilder {
    fn default() -> Self {
        Self {
            allow_http: true,
            allow_https: true,
            allowed_hosts: Vec::new(),
            denied_hosts: Vec::new(),
            allowed_ports: vec![80, 443],
            denied_ports: Vec::new(),
            allowed_ip_ranges: Vec::new(),
            denied_ip_ranges: Vec::new(),
            allow_private_ip_ranges: false,
            allow_ip_default: true,
        }
    }
}

impl HttpAclBuilder {
    /// Create a new [`HttpAclBuilder`](HttpAclBuilder).
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets whether HTTP is allowed.
    pub fn http(mut self, allow: bool) -> Self {
        self.allow_http = allow;
        self
    }

    /// Allows HTTP.
    pub fn allow_http(self) -> Self {
        self.http(true)
    }

    /// Denies HTTP.
    pub fn deny_http(self) -> Self {
        self.http(false)
    }

    /// Sets whether HTTPS is allowed.
    pub fn https(mut self, allow: bool) -> Self {
        self.allow_https = allow;
        self
    }

    /// Allows HTTPS.
    pub fn allow_https(self) -> Self {
        self.https(true)
    }

    /// Denies HTTPS.
    pub fn deny_https(self) -> Self {
        self.https(false)
    }

    /// Sets whether private IP ranges are allowed.
    pub fn private_ip_ranges(mut self, allow: bool) -> Self {
        self.allow_private_ip_ranges = allow;
        self
    }

    /// Allows private IP ranges.
    pub fn allow_private_ip_ranges(self) -> Self {
        self.private_ip_ranges(true)
    }

    /// Denies private IP ranges.
    pub fn deny_private_ip_ranges(self) -> Self {
        self.private_ip_ranges(false)
    }

    /// Set default action for IP addresses if no ACL match is found.
    pub fn ip_default(mut self, allow: bool) -> Self {
        self.allow_ip_default = allow;
        self
    }

    /// Allows IP addresses by default.
    pub fn allow_ip_default(self) -> Self {
        self.ip_default(true)
    }

    /// Denies IP addresses by default.
    pub fn deny_ip_default(self) -> Self {
        self.ip_default(false)
    }

    /// Sets whether public IP ranges are allowed.
    pub fn add_allowed_host(mut self, host: String) -> Result<Self, AddError> {
        if utils::valid::is_valid_host(&host) {
            if self.denied_hosts.contains(&host) {
                Err(AddError::AlreadyDenied)
            } else if self.allowed_hosts.contains(&host) {
                Err(AddError::AlreadyAllowed)
            } else {
                self.allowed_hosts.push(host);
                Ok(self)
            }
        } else {
            Err(AddError::Invalid)
        }
    }

    /// Removes a host from the allowed hosts.
    pub fn remove_allowed_host(mut self, host: String) -> Self {
        self.allowed_hosts.retain(|h| h != &host);
        self
    }

    /// Sets the allowed hosts.
    pub fn allowed_hosts(mut self, hosts: Vec<String>) -> Result<Self, AddError> {
        for host in &hosts {
            if utils::valid::is_valid_host(host) {
                if self.denied_hosts.contains(host) {
                    return Err(AddError::AlreadyDenied);
                } else if self.allowed_hosts.contains(host) {
                    return Err(AddError::AlreadyAllowed);
                }
            } else {
                return Err(AddError::Invalid);
            }
        }
        self.allowed_hosts = hosts;
        Ok(self)
    }

    /// Clears the allowed hosts.
    pub fn clear_allowed_hosts(mut self) -> Self {
        self.allowed_hosts.clear();
        self
    }

    /// Adds a host to the denied hosts.
    pub fn add_denied_host(mut self, host: String) -> Result<Self, AddError> {
        if utils::valid::is_valid_host(&host) {
            if self.allowed_hosts.contains(&host) {
                Err(AddError::AlreadyAllowed)
            } else if self.denied_hosts.contains(&host) {
                Err(AddError::AlreadyDenied)
            } else {
                self.denied_hosts.push(host);
                Ok(self)
            }
        } else {
            Err(AddError::Invalid)
        }
    }

    /// Removes a host from the denied hosts.
    pub fn remove_denied_host(mut self, host: String) -> Self {
        self.denied_hosts.retain(|h| h != &host);
        self
    }

    /// Sets the denied hosts.
    pub fn denied_hosts(mut self, hosts: Vec<String>) -> Result<Self, AddError> {
        for host in &hosts {
            if utils::valid::is_valid_host(host) {
                if self.allowed_hosts.contains(host) {
                    return Err(AddError::AlreadyAllowed);
                } else if self.denied_hosts.contains(host) {
                    return Err(AddError::AlreadyDenied);
                }
            } else {
                return Err(AddError::Invalid);
            }
        }
        self.denied_hosts = hosts;
        Ok(self)
    }

    /// Clears the denied hosts.
    pub fn clear_denied_hosts(mut self) -> Self {
        self.denied_hosts.clear();
        self
    }

    /// Adds a port to the allowed ports.
    pub fn add_allowed_port(mut self, port: u16) -> Result<Self, AddError> {
        if self.denied_ports.contains(&port) {
            Err(AddError::AlreadyDenied)
        } else if self.allowed_ports.contains(&port) {
            Err(AddError::AlreadyAllowed)
        } else {
            self.allowed_ports.push(port);
            Ok(self)
        }
    }

    /// Removes a port from the allowed ports.
    pub fn remove_allowed_port(mut self, port: u16) -> Self {
        self.allowed_ports.retain(|p| p != &port);
        self
    }

    /// Sets the allowed ports.
    pub fn allowed_ports(mut self, ports: Vec<u16>) -> Result<Self, AddError> {
        for port in &ports {
            if self.denied_ports.contains(port) {
                return Err(AddError::AlreadyDenied);
            } else if self.allowed_ports.contains(port) {
                return Err(AddError::AlreadyAllowed);
            }
        }
        self.allowed_ports = ports;
        Ok(self)
    }

    /// Clears the allowed ports.
    pub fn clear_allowed_ports(mut self) -> Self {
        self.allowed_ports.clear();
        self
    }

    /// Adds a port to the denied ports.
    pub fn add_denied_port(mut self, port: u16) -> Result<Self, AddError> {
        if self.allowed_ports.contains(&port) {
            Err(AddError::AlreadyAllowed)
        } else if self.denied_ports.contains(&port) {
            Err(AddError::AlreadyDenied)
        } else {
            self.denied_ports.push(port);
            Ok(self)
        }
    }

    /// Removes a port from the denied ports.
    pub fn remove_denied_port(mut self, port: u16) -> Self {
        self.denied_ports.retain(|p| p != &port);
        self
    }

    /// Sets the denied ports.
    pub fn denied_ports(mut self, ports: Vec<u16>) -> Result<Self, AddError> {
        for port in &ports {
            if self.allowed_ports.contains(port) {
                return Err(AddError::AlreadyAllowed);
            } else if self.denied_ports.contains(port) {
                return Err(AddError::AlreadyDenied);
            }
        }
        self.denied_ports = ports;
        Ok(self)
    }

    /// Clears the denied ports.
    pub fn clear_denied_ports(mut self) -> Self {
        self.denied_ports.clear();
        self
    }

    /// Adds an IP range to the allowed IP ranges.
    pub fn add_allowed_ip_range(mut self, ip_range: IpNet) -> Result<Self, AddError> {
        if self.denied_ip_ranges.contains(&ip_range) {
            return Err(AddError::AlreadyDenied);
        } else if self.allowed_ip_ranges.contains(&ip_range) {
            return Err(AddError::AlreadyAllowed);
        }
        self.allowed_ip_ranges.push(ip_range);
        Ok(self)
    }

    /// Removes an IP range from the allowed IP ranges.
    pub fn remove_allowed_ip_range(mut self, ip_range: IpNet) -> Self {
        self.allowed_ip_ranges.retain(|ip| ip != &ip_range);
        self
    }

    /// Sets the allowed IP ranges.
    pub fn allowed_ip_ranges(mut self, ip_ranges: Vec<IpNet>) -> Self {
        self.allowed_ip_ranges = ip_ranges;
        self
    }

    /// Clears the allowed IP ranges.
    pub fn clear_allowed_ip_ranges(mut self) -> Self {
        self.allowed_ip_ranges.clear();
        self
    }

    /// Adds an IP range to the denied IP ranges.
    pub fn add_denied_ip_range(mut self, ip_range: IpNet) -> Result<Self, AddError> {
        if self.allowed_ip_ranges.contains(&ip_range) {
            return Err(AddError::AlreadyAllowed);
        } else if self.denied_ip_ranges.contains(&ip_range) {
            return Err(AddError::AlreadyDenied);
        }
        self.denied_ip_ranges.push(ip_range);
        Ok(self)
    }

    /// Removes an IP range from the denied IP ranges.
    pub fn remove_denied_ip_range(mut self, ip_range: IpNet) -> Self {
        self.denied_ip_ranges.retain(|ip| ip != &ip_range);
        self
    }

    /// Sets the denied IP ranges.
    pub fn denied_ip_ranges(mut self, ip_ranges: Vec<IpNet>) -> Result<Self, AddError> {
        for ip_range in &ip_ranges {
            if self.allowed_ip_ranges.contains(ip_range) {
                return Err(AddError::AlreadyAllowed);
            } else if self.denied_ip_ranges.contains(ip_range) {
                return Err(AddError::AlreadyDenied);
            }
        }
        self.denied_ip_ranges = ip_ranges;
        Ok(self)
    }

    /// Clears the denied IP ranges.
    pub fn clear_denied_ip_ranges(mut self) -> Self {
        self.denied_ip_ranges.clear();
        self
    }

    /// Builds the [`HttpAcl`](HttpAcl).
    pub fn build(self) -> HttpAcl {
        HttpAcl {
            allow_http: self.allow_http,
            allow_https: self.allow_https,
            allowed_hosts: self.allowed_hosts,
            denied_hosts: self.denied_hosts,
            allowed_ports: self.allowed_ports,
            denied_ports: self.denied_ports,
            allowed_ip_ranges: self.allowed_ip_ranges,
            denied_ip_ranges: self.denied_ip_ranges,
            allow_private_ip_ranges: self.allow_private_ip_ranges,
            allow_ip_default: self.allow_ip_default,
        }
    }
}