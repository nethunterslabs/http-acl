use std::net::IpAddr;

use ipnet::IpNet;

use crate::{error::AddError, utils};

#[derive(Debug)]
pub struct HttpAcl {
    allow_http: bool,
    allow_https: bool,
    allowed_methods: Vec<HttpRequestMethods>,
    denied_methods: Vec<HttpRequestMethods>,
    allowed_hosts: Vec<String>,
    denied_hosts: Vec<String>,
    allowed_ports: Vec<u16>,
    denied_ports: Vec<u16>,
    allowed_ip_ranges: Vec<IpNet>,
    denied_ip_ranges: Vec<IpNet>,
    allow_private_ip_ranges: bool,
    method_acl_default: bool,
    host_acl_default: bool,
    port_acl_default: bool,
    ip_acl_default: bool,
}

impl std::default::Default for HttpAcl {
    fn default() -> Self {
        Self {
            allow_http: true,
            allow_https: true,
            allowed_methods: vec![
                HttpRequestMethods::CONNECT,
                HttpRequestMethods::DELETE,
                HttpRequestMethods::GET,
                HttpRequestMethods::HEAD,
                HttpRequestMethods::OPTIONS,
                HttpRequestMethods::PATCH,
                HttpRequestMethods::POST,
                HttpRequestMethods::PUT,
                HttpRequestMethods::TRACE,
            ],
            denied_methods: Vec::new(),
            allowed_hosts: Vec::new(),
            denied_hosts: Vec::new(),
            allowed_ports: vec![80, 443],
            denied_ports: Vec::new(),
            allowed_ip_ranges: Vec::new(),
            denied_ip_ranges: Vec::new(),
            allow_private_ip_ranges: false,
            method_acl_default: false,
            host_acl_default: false,
            port_acl_default: false,
            ip_acl_default: false,
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

    /// Returns the default action for HTTP methods if no ACL match is found.
    pub fn method_acl_default(&self) -> bool {
        self.method_acl_default
    }

    /// Returns the default action for hosts if no ACL match is found.
    pub fn host_acl_default(&self) -> bool {
        self.host_acl_default
    }

    /// Returns the default action for ports if no ACL match is found.
    pub fn port_acl_default(&self) -> bool {
        self.port_acl_default
    }

    /// Returns the default action for IPs if no ACL match is found.
    pub fn ip_acl_default(&self) -> bool {
        self.ip_acl_default
    }

    /// Returns the allowed methods.
    pub fn allowed_methods(&self) -> &[HttpRequestMethods] {
        &self.allowed_methods
    }

    /// Returns the denied methods.
    pub fn denied_methods(&self) -> &[HttpRequestMethods] {
        &self.denied_methods
    }

    /// Returns whether the scheme is allowed.
    pub fn is_scheme_allowed(&self, scheme: &str) -> AclClassification {
        if scheme == "http" && self.allow_http || scheme == "https" && self.allow_https {
            AclClassification::AllowedUserAcl
        } else {
            AclClassification::DeniedUserAcl
        }
    }

    /// Returns whether the method is allowed.
    pub fn is_method_allowed(&self, method: &HttpRequestMethods) -> AclClassification {
        if self.allowed_methods.contains(method) {
            AclClassification::AllowedUserAcl
        } else if self.denied_methods.contains(method) {
            AclClassification::DeniedUserAcl
        } else if self.method_acl_default {
            AclClassification::AllowedDefault
        } else {
            AclClassification::DeniedDefault
        }
    }

    /// Returns whether the host is allowed.
    pub fn is_host_allowed(&self, host: &str) -> AclClassification {
        if self.denied_hosts.contains(&host.to_string()) {
            AclClassification::DeniedUserAcl
        } else if self.allowed_hosts.contains(&host.to_string()) {
            AclClassification::AllowedUserAcl
        } else if self.host_acl_default {
            AclClassification::AllowedDefault
        } else {
            AclClassification::DeniedDefault
        }
    }

    /// Returns whether the port is allowed.
    pub fn is_port_allowed(&self, port: u16) -> AclClassification {
        if self.denied_ports.contains(&port) {
            AclClassification::DeniedUserAcl
        } else if self.allowed_ports.contains(&port) {
            AclClassification::AllowedUserAcl
        } else if self.port_acl_default {
            AclClassification::AllowedDefault
        } else {
            AclClassification::DeniedDefault
        }
    }

    /// Returns whether an IP is allowed.
    pub fn is_ip_allowed(&self, ip: &IpAddr) -> AclClassification {
        if (!utils::ip::is_global_ip(ip) || ip.is_loopback()) && !utils::ip::is_private_ip(ip) {
            if Self::is_ip_in_ranges(ip, &self.allowed_ip_ranges) {
                return AclClassification::AllowedUserAcl;
            } else {
                return AclClassification::DeniedNotGlobal;
            }
        }

        if Self::is_ip_in_ranges(ip, &self.allowed_ip_ranges) {
            AclClassification::AllowedUserAcl
        } else if Self::is_ip_in_ranges(ip, &self.denied_ip_ranges) {
            AclClassification::DeniedUserAcl
        } else if utils::ip::is_private_ip(ip) && !self.allow_private_ip_ranges {
            AclClassification::DeniedPrivateRange
        } else if self.ip_acl_default {
            AclClassification::AllowedDefault
        } else {
            AclClassification::DeniedDefault
        }
    }

    /// Checks if an ip is in a list of ip ranges.
    fn is_ip_in_ranges(ip: &IpAddr, ranges: &[IpNet]) -> bool {
        ranges.iter().any(|range| range.contains(ip))
    }
}

/// Represents an IP ACL Classification.
#[non_exhaustive]
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum AclClassification {
    /// The entiy is allowed according to the allowed ACL.
    AllowedUserAcl,
    /// The entity is allowed because the default is to allow if no ACL match is found.
    AllowedDefault,
    /// The entiy is denied according to the denied ACL.
    DeniedUserAcl,
    /// The ip is denied because it is not global.
    DeniedNotGlobal,
    /// The ip is denied because it is in a private range.
    DeniedPrivateRange,
    /// The entity is denied because the default is to deny if no ACL match is found.
    DeniedDefault,
    /// The entiy is denied.
    Denied(String),
}

impl std::fmt::Display for AclClassification {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AclClassification::AllowedUserAcl => {
                write!(f, "The entiy is allowed according to the allowed ACL.")
            }
            AclClassification::AllowedDefault => write!(
                f,
                "The entity is allowed because the default is to allow if no ACL match is found."
            ),
            AclClassification::DeniedUserAcl => {
                write!(f, "The entiy is denied according to the denied ACL.")
            }
            AclClassification::DeniedNotGlobal => {
                write!(f, "The ip is denied because it is not global.")
            }
            AclClassification::DeniedPrivateRange => {
                write!(f, "The ip is denied because it is in a private range.")
            }
            AclClassification::DeniedDefault => write!(
                f,
                "The entity is denied because the default is to deny if no ACL match is found."
            ),
            AclClassification::Denied(reason) => {
                write!(f, "The entiy is denied because {}.", reason)
            }
        }
    }
}

impl AclClassification {
    /// Returns whether the IP is allowed.
    pub fn is_allowed(&self) -> bool {
        matches!(
            self,
            AclClassification::AllowedUserAcl | AclClassification::AllowedDefault
        )
    }

    /// Returns whether the IP is denied.
    pub fn is_denied(&self) -> bool {
        matches!(
            self,
            AclClassification::DeniedUserAcl
                | AclClassification::Denied(_)
                | AclClassification::DeniedDefault
                | AclClassification::DeniedNotGlobal
                | AclClassification::DeniedPrivateRange
        )
    }
}

/// Represents an HTTP request method.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum HttpRequestMethods {
    CONNECT,
    DELETE,
    GET,
    HEAD,
    OPTIONS,
    PATCH,
    POST,
    PUT,
    TRACE,
    OTHER(String),
}

/// A builder for [`HttpAcl`](HttpAcl).
#[derive(Debug)]
pub struct HttpAclBuilder {
    allow_http: bool,
    allow_https: bool,
    allowed_methods: Vec<HttpRequestMethods>,
    denied_methods: Vec<HttpRequestMethods>,
    allowed_hosts: Vec<String>,
    denied_hosts: Vec<String>,
    allowed_ports: Vec<u16>,
    denied_ports: Vec<u16>,
    allowed_ip_ranges: Vec<IpNet>,
    denied_ip_ranges: Vec<IpNet>,
    allow_private_ip_ranges: bool,
    method_acl_default: bool,
    host_acl_default: bool,
    port_acl_default: bool,
    ip_acl_default: bool,
}

impl std::default::Default for HttpAclBuilder {
    fn default() -> Self {
        Self {
            allow_http: true,
            allow_https: true,
            allowed_methods: vec![
                HttpRequestMethods::CONNECT,
                HttpRequestMethods::DELETE,
                HttpRequestMethods::GET,
                HttpRequestMethods::HEAD,
                HttpRequestMethods::OPTIONS,
                HttpRequestMethods::PATCH,
                HttpRequestMethods::POST,
                HttpRequestMethods::PUT,
                HttpRequestMethods::TRACE,
            ],
            denied_methods: Vec::new(),
            allowed_hosts: Vec::new(),
            denied_hosts: Vec::new(),
            allowed_ports: vec![80, 443],
            denied_ports: Vec::new(),
            allowed_ip_ranges: Vec::new(),
            denied_ip_ranges: Vec::new(),
            allow_private_ip_ranges: false,
            method_acl_default: false,
            host_acl_default: false,
            port_acl_default: false,
            ip_acl_default: false,
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

    /// Sets whether HTTPS is allowed.
    pub fn https(mut self, allow: bool) -> Self {
        self.allow_https = allow;
        self
    }

    /// Sets whether private IP ranges are allowed.
    pub fn private_ip_ranges(mut self, allow: bool) -> Self {
        self.allow_private_ip_ranges = allow;
        self
    }

    /// Set default action for HTTP methods if no ACL match is found.
    pub fn method_acl_default(mut self, allow: bool) -> Self {
        self.method_acl_default = allow;
        self
    }

    /// Set default action for hosts if no ACL match is found.
    pub fn host_acl_default(mut self, allow: bool) -> Self {
        self.host_acl_default = allow;
        self
    }

    /// Set default action for ports if no ACL match is found.
    pub fn port_acl_default(mut self, allow: bool) -> Self {
        self.port_acl_default = allow;
        self
    }

    /// Set default action for IPs if no ACL match is found.
    pub fn ip_acl_default(mut self, allow: bool) -> Self {
        self.ip_acl_default = allow;
        self
    }

    /// Adds a method to the allowed methods.
    pub fn add_allowed_method(mut self, method: HttpRequestMethods) -> Result<Self, AddError> {
        if self.denied_methods.contains(&method) {
            Err(AddError::AlreadyDenied)
        } else if self.allowed_methods.contains(&method) {
            Err(AddError::AlreadyAllowed)
        } else {
            self.allowed_methods.push(method);
            Ok(self)
        }
    }

    /// Removes a method from the allowed methods.
    pub fn remove_allowed_method(mut self, method: HttpRequestMethods) -> Self {
        self.allowed_methods.retain(|m| m != &method);
        self
    }

    /// Sets the allowed methods.
    pub fn allowed_methods(mut self, methods: Vec<HttpRequestMethods>) -> Result<Self, AddError> {
        for method in &methods {
            if self.denied_methods.contains(method) {
                return Err(AddError::AlreadyDenied);
            } else if self.allowed_methods.contains(method) {
                return Err(AddError::AlreadyAllowed);
            }
        }
        self.allowed_methods = methods;
        Ok(self)
    }

    /// Clears the allowed methods.
    pub fn clear_allowed_methods(mut self) -> Self {
        self.allowed_methods.clear();
        self
    }

    /// Sets whether public IP ranges are allowed.
    pub fn add_allowed_host(mut self, host: String) -> Result<Self, AddError> {
        if utils::authority::is_valid_host(&host) {
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
            if utils::authority::is_valid_host(host) {
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
        if utils::authority::is_valid_host(&host) {
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
            if utils::authority::is_valid_host(host) {
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
            allowed_methods: self.allowed_methods,
            denied_methods: self.denied_methods,
            allowed_hosts: self.allowed_hosts,
            denied_hosts: self.denied_hosts,
            allowed_ports: self.allowed_ports,
            denied_ports: self.denied_ports,
            allowed_ip_ranges: self.allowed_ip_ranges,
            denied_ip_ranges: self.denied_ip_ranges,
            allow_private_ip_ranges: self.allow_private_ip_ranges,
            method_acl_default: self.method_acl_default,
            host_acl_default: self.host_acl_default,
            port_acl_default: self.port_acl_default,
            ip_acl_default: self.ip_acl_default,
        }
    }
}
