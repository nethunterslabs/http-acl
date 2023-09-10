use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::ops::RangeInclusive;

use ipnet::IpNet;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::{error::AddError, utils};

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct HttpAcl {
    allow_http: bool,
    allow_https: bool,
    allowed_methods: Vec<HttpRequestMethod>,
    denied_methods: Vec<HttpRequestMethod>,
    allowed_hosts: Vec<String>,
    denied_hosts: Vec<String>,
    allowed_port_ranges: Vec<RangeInclusive<u16>>,
    denied_port_ranges: Vec<RangeInclusive<u16>>,
    allowed_ip_ranges: Vec<IpNet>,
    denied_ip_ranges: Vec<IpNet>,
    allow_private_ip_ranges: bool,
    static_dns_mapping: HashMap<String, SocketAddr>,
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
                HttpRequestMethod::CONNECT,
                HttpRequestMethod::DELETE,
                HttpRequestMethod::GET,
                HttpRequestMethod::HEAD,
                HttpRequestMethod::OPTIONS,
                HttpRequestMethod::PATCH,
                HttpRequestMethod::POST,
                HttpRequestMethod::PUT,
                HttpRequestMethod::TRACE,
            ],
            denied_methods: Vec::new(),
            allowed_hosts: Vec::new(),
            denied_hosts: Vec::new(),
            allowed_port_ranges: vec![80..=80, 443..=443],
            denied_port_ranges: Vec::new(),
            allowed_ip_ranges: Vec::new(),
            denied_ip_ranges: Vec::new(),
            allow_private_ip_ranges: false,
            static_dns_mapping: HashMap::new(),
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
        HttpAclBuilder::new()
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
    pub fn allowed_methods(&self) -> &[HttpRequestMethod] {
        &self.allowed_methods
    }

    /// Returns the denied methods.
    pub fn denied_methods(&self) -> &[HttpRequestMethod] {
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
    pub fn is_method_allowed(&self, method: impl Into<HttpRequestMethod>) -> AclClassification {
        let method = method.into();
        if self.allowed_methods.contains(&method) {
            AclClassification::AllowedUserAcl
        } else if self.denied_methods.contains(&method) {
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
        if Self::is_port_in_ranges(port, &self.denied_port_ranges) {
            AclClassification::DeniedUserAcl
        } else if Self::is_port_in_ranges(port, &self.allowed_port_ranges) {
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

    /// Resolve static DNS mapping.
    pub fn resolve_static_dns_mapping(&self, host: &str) -> Option<SocketAddr> {
        self.static_dns_mapping.get(host).copied()
    }

    /// Checks if an ip is in a list of ip ranges.
    fn is_ip_in_ranges(ip: &IpAddr, ranges: &[IpNet]) -> bool {
        ranges.iter().any(|range| range.contains(ip))
    }

    /// Checks if a port is in a list of port ranges.
    fn is_port_in_ranges(port: u16, ranges: &[RangeInclusive<u16>]) -> bool {
        ranges.iter().any(|range| range.contains(&port))
    }
}

/// Represents an ACL Classification.
#[non_exhaustive]
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum AclClassification {
    /// The entiy is allowed according to the allowed ACL.
    AllowedUserAcl,
    /// The entity is allowed because the default is to allow if no ACL match is found.
    AllowedDefault,
    /// The entiy is denied according to the denied ACL.
    DeniedUserAcl,
    /// The entity is denied because the default is to deny if no ACL match is found.
    DeniedDefault,
    /// The entiy is denied.
    Denied(String),
    /// The IP is denied because it is not global.
    DeniedNotGlobal,
    /// The IP is denied because it is in a private range.
    DeniedPrivateRange,
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
    /// Returns whether the classification is allowed.
    pub fn is_allowed(&self) -> bool {
        matches!(
            self,
            AclClassification::AllowedUserAcl | AclClassification::AllowedDefault
        )
    }

    /// Returns whether the classification is denied.
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
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum HttpRequestMethod {
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

impl From<&str> for HttpRequestMethod {
    fn from(method: &str) -> Self {
        match method {
            "CONNECT" => HttpRequestMethod::CONNECT,
            "DELETE" => HttpRequestMethod::DELETE,
            "GET" => HttpRequestMethod::GET,
            "HEAD" => HttpRequestMethod::HEAD,
            "OPTIONS" => HttpRequestMethod::OPTIONS,
            "PATCH" => HttpRequestMethod::PATCH,
            "POST" => HttpRequestMethod::POST,
            "PUT" => HttpRequestMethod::PUT,
            "TRACE" => HttpRequestMethod::TRACE,
            _ => HttpRequestMethod::OTHER(method.to_string()),
        }
    }
}

/// A builder for [`HttpAcl`](HttpAcl).
#[derive(Default, Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct HttpAclBuilder {
    allow_http: bool,
    allow_https: bool,
    allowed_methods: Vec<HttpRequestMethod>,
    denied_methods: Vec<HttpRequestMethod>,
    allowed_hosts: Vec<String>,
    denied_hosts: Vec<String>,
    allowed_port_ranges: Vec<RangeInclusive<u16>>,
    denied_port_ranges: Vec<RangeInclusive<u16>>,
    allowed_ip_ranges: Vec<IpNet>,
    denied_ip_ranges: Vec<IpNet>,
    allow_private_ip_ranges: bool,
    static_dns_mapping: HashMap<String, SocketAddr>,
    method_acl_default: bool,
    host_acl_default: bool,
    port_acl_default: bool,
    ip_acl_default: bool,
}

impl HttpAclBuilder {
    /// Create a new [`HttpAclBuilder`](HttpAclBuilder).
    pub fn new() -> Self {
        Self {
            allow_http: true,
            allow_https: true,
            allowed_methods: vec![
                HttpRequestMethod::CONNECT,
                HttpRequestMethod::DELETE,
                HttpRequestMethod::GET,
                HttpRequestMethod::HEAD,
                HttpRequestMethod::OPTIONS,
                HttpRequestMethod::PATCH,
                HttpRequestMethod::POST,
                HttpRequestMethod::PUT,
                HttpRequestMethod::TRACE,
            ],
            denied_methods: Vec::new(),
            allowed_hosts: Vec::new(),
            denied_hosts: Vec::new(),
            allowed_port_ranges: vec![80..=80, 443..=443],
            denied_port_ranges: Vec::new(),
            allowed_ip_ranges: Vec::new(),
            denied_ip_ranges: Vec::new(),
            allow_private_ip_ranges: false,
            static_dns_mapping: HashMap::new(),
            method_acl_default: false,
            host_acl_default: false,
            port_acl_default: false,
            ip_acl_default: false,
        }
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
    pub fn add_allowed_method(
        mut self,
        method: impl Into<HttpRequestMethod>,
    ) -> Result<Self, AddError> {
        let method = method.into();
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
    pub fn remove_allowed_method(mut self, method: impl Into<HttpRequestMethod>) -> Self {
        let method = method.into();
        self.allowed_methods.retain(|m| m != &method);
        self
    }

    /// Sets the allowed methods.
    pub fn allowed_methods(
        mut self,
        methods: Vec<impl Into<HttpRequestMethod>>,
    ) -> Result<Self, AddError> {
        let methods = methods.into_iter().map(|m| m.into()).collect::<Vec<_>>();

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

    /// Adds a method to the denied methods.
    pub fn add_denied_method(
        mut self,
        method: impl Into<HttpRequestMethod>,
    ) -> Result<Self, AddError> {
        let method = method.into();
        if self.allowed_methods.contains(&method) {
            Err(AddError::AlreadyAllowed)
        } else if self.denied_methods.contains(&method) {
            Err(AddError::AlreadyDenied)
        } else {
            self.denied_methods.push(method);
            Ok(self)
        }
    }

    /// Removes a method from the denied methods.
    pub fn remove_denied_method(mut self, method: impl Into<HttpRequestMethod>) -> Self {
        let method = method.into();
        self.denied_methods.retain(|m| m != &method);
        self
    }

    /// Sets the denied methods.
    pub fn denied_methods(
        mut self,
        methods: Vec<impl Into<HttpRequestMethod>>,
    ) -> Result<Self, AddError> {
        let methods = methods.into_iter().map(|m| m.into()).collect::<Vec<_>>();

        for method in &methods {
            if self.allowed_methods.contains(method) {
                return Err(AddError::AlreadyAllowed);
            } else if self.denied_methods.contains(method) {
                return Err(AddError::AlreadyDenied);
            }
        }
        self.denied_methods = methods;
        Ok(self)
    }

    /// Clears the denied methods.
    pub fn clear_denied_methods(mut self) -> Self {
        self.denied_methods.clear();
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

    /// Adds a port range to the allowed port ranges.
    pub fn add_allowed_port_range(
        mut self,
        port_range: RangeInclusive<u16>,
    ) -> Result<Self, AddError> {
        if self.denied_port_ranges.contains(&port_range) {
            Err(AddError::AlreadyDenied)
        } else if self.allowed_port_ranges.contains(&port_range) {
            Err(AddError::AlreadyAllowed)
        } else {
            self.allowed_port_ranges.push(port_range);
            Ok(self)
        }
    }

    /// Removes a port range from the allowed port ranges.
    pub fn remove_allowed_port_range(mut self, port_range: RangeInclusive<u16>) -> Self {
        self.allowed_port_ranges.retain(|p| p != &port_range);
        self
    }

    /// Sets the allowed port ranges.
    pub fn allowed_port_ranges(
        mut self,
        port_ranges: Vec<RangeInclusive<u16>>,
    ) -> Result<Self, AddError> {
        for port_range in &port_ranges {
            if self.denied_port_ranges.contains(port_range) {
                return Err(AddError::AlreadyDenied);
            } else if self.allowed_port_ranges.contains(port_range) {
                return Err(AddError::AlreadyAllowed);
            }
        }
        self.allowed_port_ranges = port_ranges;
        Ok(self)
    }

    /// Clears the allowed port ranges.
    pub fn clear_allowed_port_ranges(mut self) -> Self {
        self.allowed_port_ranges.clear();
        self
    }

    /// Adds a port range to the denied port ranges.
    pub fn add_denied_port_range(
        mut self,
        port_range: RangeInclusive<u16>,
    ) -> Result<Self, AddError> {
        if self.allowed_port_ranges.contains(&port_range) {
            Err(AddError::AlreadyAllowed)
        } else if self.denied_port_ranges.contains(&port_range) {
            Err(AddError::AlreadyDenied)
        } else {
            self.denied_port_ranges.push(port_range);
            Ok(self)
        }
    }

    /// Removes a port range from the denied port ranges.
    pub fn remove_denied_port_range(mut self, port_range: RangeInclusive<u16>) -> Self {
        self.denied_port_ranges.retain(|p| p != &port_range);
        self
    }

    /// Sets the denied port ranges.
    pub fn denied_port_ranges(
        mut self,
        port_ranges: Vec<RangeInclusive<u16>>,
    ) -> Result<Self, AddError> {
        for port_range in &port_ranges {
            if self.allowed_port_ranges.contains(port_range) {
                return Err(AddError::AlreadyAllowed);
            } else if self.denied_port_ranges.contains(port_range) {
                return Err(AddError::AlreadyDenied);
            }
        }
        self.denied_port_ranges = port_ranges;
        Ok(self)
    }

    /// Clears the denied port ranges.
    pub fn clear_denied_port_ranges(mut self) -> Self {
        self.denied_port_ranges.clear();
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
    pub fn allowed_ip_ranges(mut self, ip_ranges: Vec<IpNet>) -> Result<Self, AddError> {
        for ip_range in &ip_ranges {
            if self.denied_ip_ranges.contains(ip_range) {
                return Err(AddError::AlreadyDenied);
            } else if self.allowed_ip_ranges.contains(ip_range) {
                return Err(AddError::AlreadyAllowed);
            }
        }
        self.allowed_ip_ranges = ip_ranges;
        Ok(self)
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

    /// Add a static DNS mapping.
    pub fn add_static_dns_mapping(
        mut self,
        host: String,
        sock_addr: SocketAddr,
    ) -> Result<Self, AddError> {
        if utils::authority::is_valid_host(&host) {
            self.static_dns_mapping.insert(host, sock_addr);
            Ok(self)
        } else {
            Err(AddError::Invalid)
        }
    }

    /// Removes a static DNS mapping.
    pub fn remove_static_dns_mapping(mut self, host: &str) -> Self {
        self.static_dns_mapping.remove(host);
        self
    }

    /// Sets the static DNS mappings.
    pub fn static_dns_mappings(
        mut self,
        mappings: HashMap<String, SocketAddr>,
    ) -> Result<Self, AddError> {
        for (host, ip) in &mappings {
            if utils::authority::is_valid_host(host) {
                self.static_dns_mapping.insert(host.to_string(), *ip);
            } else {
                return Err(AddError::Invalid);
            }
        }
        Ok(self)
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
            allowed_port_ranges: self.allowed_port_ranges,
            denied_port_ranges: self.denied_port_ranges,
            allowed_ip_ranges: self.allowed_ip_ranges,
            denied_ip_ranges: self.denied_ip_ranges,
            allow_private_ip_ranges: self.allow_private_ip_ranges,
            static_dns_mapping: self.static_dns_mapping,
            method_acl_default: self.method_acl_default,
            host_acl_default: self.host_acl_default,
            port_acl_default: self.port_acl_default,
            ip_acl_default: self.ip_acl_default,
        }
    }

    /// Builds the [`HttpAcl`](HttpAcl) and returns an error if the configuration is invalid.
    /// This can be used as a validity check for deserialized ACLs that were genrated externally.
    pub fn try_build(self) -> Result<HttpAcl, AddError> {
        for method in &self.allowed_methods {
            if self.denied_methods.contains(method) {
                return Err(AddError::AlreadyDenied);
            }
        }
        for method in &self.denied_methods {
            if self.allowed_methods.contains(method) {
                return Err(AddError::AlreadyAllowed);
            }
        }
        for host in &self.allowed_hosts {
            if self.denied_hosts.contains(host) {
                return Err(AddError::AlreadyDenied);
            }
        }
        for host in &self.denied_hosts {
            if self.allowed_hosts.contains(host) {
                return Err(AddError::AlreadyAllowed);
            }
        }
        for port_range in &self.allowed_port_ranges {
            if self.denied_port_ranges.contains(port_range) {
                return Err(AddError::AlreadyDenied);
            }
        }
        for port_range in &self.denied_port_ranges {
            if self.allowed_port_ranges.contains(port_range) {
                return Err(AddError::AlreadyAllowed);
            }
        }
        for ip_range in &self.allowed_ip_ranges {
            if self.denied_ip_ranges.contains(ip_range) {
                return Err(AddError::AlreadyDenied);
            }
        }
        for ip_range in &self.denied_ip_ranges {
            if self.allowed_ip_ranges.contains(ip_range) {
                return Err(AddError::AlreadyAllowed);
            }
        }
        Ok(self.build())
    }
}
