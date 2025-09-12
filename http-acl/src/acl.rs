//! Contains the [`HttpAcl`], [`HttpAclBuilder`],
//! and related types.

#[cfg(feature = "hashbrown")]
use hashbrown::{HashMap, HashSet, hash_map::Entry};
#[cfg(not(feature = "hashbrown"))]
use std::collections::{HashMap, HashSet, hash_map::Entry};
use std::hash::Hash;
use std::net::{IpAddr, SocketAddr};
use std::ops::RangeInclusive;
use std::sync::Arc;

use matchit::Router;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::{
    error::AddError,
    utils::{self, IntoIpRange, authority::Authority},
};

/// A function that validates an HTTP request against an ACL.
pub type ValidateFn = Arc<
    dyn for<'h> Fn(
            &str,
            &Authority,
            Box<dyn Iterator<Item = (&'h str, &'h str)> + Send + Sync + 'h>,
            Option<&[u8]>,
        ) -> AclClassification
        + Send
        + Sync,
>;

#[derive(Clone)]
/// Represents an HTTP ACL.
pub struct HttpAcl {
    allow_http: bool,
    allow_https: bool,
    allowed_methods: HashSet<HttpRequestMethod>,
    denied_methods: HashSet<HttpRequestMethod>,
    allowed_hosts: HashSet<Box<str>>,
    denied_hosts: HashSet<Box<str>>,
    allowed_port_ranges: Box<[RangeInclusive<u16>]>,
    denied_port_ranges: Box<[RangeInclusive<u16>]>,
    allowed_ip_ranges: Box<[RangeInclusive<IpAddr>]>,
    denied_ip_ranges: Box<[RangeInclusive<IpAddr>]>,
    static_dns_mapping: HashMap<Box<str>, SocketAddr>,
    allowed_headers: HashMap<Box<str>, Option<Box<str>>>,
    denied_headers: HashMap<Box<str>, Option<Box<str>>>,
    allowed_url_paths_router: Router<()>,
    denied_url_paths_router: Router<()>,
    validate_fn: Option<ValidateFn>,
    allow_non_global_ip_ranges: bool,
    method_acl_default: bool,
    host_acl_default: bool,
    port_acl_default: bool,
    ip_acl_default: bool,
    header_acl_default: bool,
    url_path_acl_default: bool,
}

impl std::fmt::Debug for HttpAcl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpAcl")
            .field("allow_http", &self.allow_http)
            .field("allow_https", &self.allow_https)
            .field("allowed_methods", &self.allowed_methods)
            .field("denied_methods", &self.denied_methods)
            .field("allowed_hosts", &self.allowed_hosts)
            .field("denied_hosts", &self.denied_hosts)
            .field("allowed_port_ranges", &self.allowed_port_ranges)
            .field("denied_port_ranges", &self.denied_port_ranges)
            .field("allowed_ip_ranges", &self.allowed_ip_ranges)
            .field("denied_ip_ranges", &self.denied_ip_ranges)
            .field("static_dns_mapping", &self.static_dns_mapping)
            .field("allowed_headers", &self.allowed_headers)
            .field("denied_headers", &self.denied_headers)
            .field(
                "allow_non_global_ip_ranges",
                &self.allow_non_global_ip_ranges,
            )
            .field("method_acl_default", &self.method_acl_default)
            .field("host_acl_default", &self.host_acl_default)
            .field("port_acl_default", &self.port_acl_default)
            .field("ip_acl_default", &self.ip_acl_default)
            .field("header_acl_default", &self.header_acl_default)
            .field("url_path_acl_default", &self.url_path_acl_default)
            .finish()
    }
}

impl PartialEq for HttpAcl {
    fn eq(&self, other: &Self) -> bool {
        self.allow_http == other.allow_http
            && self.allow_https == other.allow_https
            && self.allowed_methods == other.allowed_methods
            && self.denied_methods == other.denied_methods
            && self.allowed_hosts == other.allowed_hosts
            && self.denied_hosts == other.denied_hosts
            && self.allowed_port_ranges == other.allowed_port_ranges
            && self.denied_port_ranges == other.denied_port_ranges
            && self.allowed_ip_ranges == other.allowed_ip_ranges
            && self.denied_ip_ranges == other.denied_ip_ranges
            && self.static_dns_mapping == other.static_dns_mapping
            && self.allowed_headers == other.allowed_headers
            && self.denied_headers == other.denied_headers
            && self.allow_non_global_ip_ranges == other.allow_non_global_ip_ranges
            && self.method_acl_default == other.method_acl_default
            && self.host_acl_default == other.host_acl_default
            && self.port_acl_default == other.port_acl_default
            && self.ip_acl_default == other.ip_acl_default
            && self.header_acl_default == other.header_acl_default
            && self.url_path_acl_default == other.url_path_acl_default
    }
}

impl std::default::Default for HttpAcl {
    fn default() -> Self {
        Self {
            allow_http: true,
            allow_https: true,
            allowed_methods: [
                HttpRequestMethod::CONNECT,
                HttpRequestMethod::DELETE,
                HttpRequestMethod::GET,
                HttpRequestMethod::HEAD,
                HttpRequestMethod::OPTIONS,
                HttpRequestMethod::PATCH,
                HttpRequestMethod::POST,
                HttpRequestMethod::PUT,
                HttpRequestMethod::TRACE,
            ]
            .into_iter()
            .collect(),
            denied_methods: HashSet::new(),
            allowed_hosts: HashSet::new(),
            denied_hosts: HashSet::new(),
            allowed_port_ranges: vec![80..=80, 443..=443].into_boxed_slice(),
            denied_port_ranges: Vec::new().into_boxed_slice(),
            allowed_ip_ranges: Vec::new().into_boxed_slice(),
            denied_ip_ranges: Vec::new().into_boxed_slice(),
            static_dns_mapping: HashMap::new(),
            allowed_headers: HashMap::new(),
            denied_headers: HashMap::new(),
            allowed_url_paths_router: Router::new(),
            denied_url_paths_router: Router::new(),
            validate_fn: None,
            allow_non_global_ip_ranges: false,
            method_acl_default: false,
            host_acl_default: false,
            port_acl_default: false,
            ip_acl_default: false,
            header_acl_default: true,
            url_path_acl_default: true,
        }
    }
}

impl HttpAcl {
    /// Returns a new [`HttpAclBuilder`].
    pub fn builder() -> HttpAclBuilder {
        HttpAclBuilder::new()
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
        if self.denied_hosts.iter().any(|h| h.as_ref() == host) {
            AclClassification::DeniedUserAcl
        } else if self.allowed_hosts.iter().any(|h| h.as_ref() == host) {
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
        if !utils::ip::is_global_ip(ip) && !self.allow_non_global_ip_ranges {
            AclClassification::DeniedNotGlobal
        } else if Self::is_ip_in_ranges(ip, &self.allowed_ip_ranges) {
            AclClassification::AllowedUserAcl
        } else if Self::is_ip_in_ranges(ip, &self.denied_ip_ranges) {
            AclClassification::DeniedUserAcl
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

    /// Returns whether a header is allowed.
    pub fn is_header_allowed(&self, header_name: &str, header_value: &str) -> AclClassification {
        if let Some(allowed_value) = self.allowed_headers.get(header_name) {
            if allowed_value.as_deref() == Some(header_value) || allowed_value.is_none() {
                AclClassification::AllowedUserAcl
            } else {
                AclClassification::DeniedUserAcl
            }
        } else if let Some(denied_value) = self.denied_headers.get(header_name) {
            if denied_value.as_deref() == Some(header_value) || denied_value.is_none() {
                AclClassification::DeniedUserAcl
            } else {
                AclClassification::AllowedUserAcl
            }
        } else if self.header_acl_default {
            AclClassification::AllowedDefault
        } else {
            AclClassification::DeniedDefault
        }
    }

    /// Returns whether a URL path is allowed.
    pub fn is_url_path_allowed(&self, url_path: &str) -> AclClassification {
        if self.allowed_url_paths_router.at(url_path).is_ok() {
            AclClassification::AllowedUserAcl
        } else if self.denied_url_paths_router.at(url_path).is_ok() {
            AclClassification::DeniedUserAcl
        } else if self.url_path_acl_default {
            AclClassification::AllowedDefault
        } else {
            AclClassification::DeniedDefault
        }
    }

    /// Returns whether a request is valid.
    pub fn is_valid<'h>(
        &self,
        scheme: &str,
        authority: &Authority,
        headers: impl Iterator<Item = (&'h str, &'h str)> + Send + Sync + 'h,
        body: Option<&[u8]>,
    ) -> AclClassification {
        if let Some(validate_fn) = &self.validate_fn {
            validate_fn(scheme, authority, Box::new(headers), body)
        } else {
            AclClassification::AllowedDefault
        }
    }

    /// Checks if an ip is in a list of ip ranges.
    fn is_ip_in_ranges(ip: &IpAddr, ranges: &[RangeInclusive<IpAddr>]) -> bool {
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
    /// The entity is allowed according to the allowed ACL.
    AllowedUserAcl,
    /// The entity is allowed because the default is to allow if no ACL match is found.
    AllowedDefault,
    /// The entity is denied according to the denied ACL.
    DeniedUserAcl,
    /// The entity is denied because the default is to deny if no ACL match is found.
    DeniedDefault,
    /// The entity is denied.
    Denied(String),
    /// The IP is denied because it is not global.
    DeniedNotGlobal,
}

impl std::fmt::Display for AclClassification {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AclClassification::AllowedUserAcl => {
                write!(f, "The entity is allowed according to the allowed ACL.")
            }
            AclClassification::AllowedDefault => write!(
                f,
                "The entity is allowed because the default is to allow if no ACL match is found."
            ),
            AclClassification::DeniedUserAcl => {
                write!(f, "The entity is denied according to the denied ACL.")
            }
            AclClassification::DeniedNotGlobal => {
                write!(f, "The ip is denied because it is not global.")
            }
            AclClassification::DeniedDefault => write!(
                f,
                "The entity is denied because the default is to deny if no ACL match is found."
            ),
            AclClassification::Denied(reason) => {
                write!(f, "The entity is denied because {reason}.")
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
        )
    }
}

/// Represents an HTTP request method.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum HttpRequestMethod {
    /// The CONNECT method.
    CONNECT,
    /// The DELETE method.
    DELETE,
    /// The GET method.
    GET,
    /// The HEAD method.
    HEAD,
    /// The OPTIONS method.
    OPTIONS,
    /// The PATCH method.
    PATCH,
    /// The POST method.
    POST,
    /// The PUT method.
    PUT,
    /// The TRACE method.
    TRACE,
    /// Any other method.
    OTHER(Box<str>),
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
            _ => HttpRequestMethod::OTHER(method.into()),
        }
    }
}

impl HttpRequestMethod {
    /// Return the method as a `&str`.
    pub fn as_str(&self) -> &str {
        match self {
            HttpRequestMethod::CONNECT => "CONNECT",
            HttpRequestMethod::DELETE => "DELETE",
            HttpRequestMethod::GET => "GET",
            HttpRequestMethod::HEAD => "HEAD",
            HttpRequestMethod::OPTIONS => "OPTIONS",
            HttpRequestMethod::PATCH => "PATCH",
            HttpRequestMethod::POST => "POST",
            HttpRequestMethod::PUT => "PUT",
            HttpRequestMethod::TRACE => "TRACE",
            HttpRequestMethod::OTHER(other) => other,
        }
    }
}

/// A builder for [`HttpAcl`].
#[derive(Default, Clone)]
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
    allowed_ip_ranges: Vec<RangeInclusive<IpAddr>>,
    denied_ip_ranges: Vec<RangeInclusive<IpAddr>>,
    static_dns_mapping: HashMap<String, SocketAddr>,
    allowed_headers: HashMap<String, Option<String>>,
    denied_headers: HashMap<String, Option<String>>,
    allowed_url_paths: Vec<String>,
    #[cfg_attr(feature = "serde", serde(skip))]
    allowed_url_paths_router: Router<()>,
    denied_url_paths: Vec<String>,
    #[cfg_attr(feature = "serde", serde(skip))]
    denied_url_paths_router: Router<()>,
    allow_non_global_ip_ranges: bool,
    method_acl_default: bool,
    host_acl_default: bool,
    port_acl_default: bool,
    ip_acl_default: bool,
    header_acl_default: bool,
    url_path_acl_default: bool,
}

impl std::fmt::Debug for HttpAclBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpAclBuilder")
            .field("allow_http", &self.allow_http)
            .field("allow_https", &self.allow_https)
            .field("allowed_methods", &self.allowed_methods)
            .field("denied_methods", &self.denied_methods)
            .field("allowed_hosts", &self.allowed_hosts)
            .field("denied_hosts", &self.denied_hosts)
            .field("allowed_port_ranges", &self.allowed_port_ranges)
            .field("denied_port_ranges", &self.denied_port_ranges)
            .field("allowed_ip_ranges", &self.allowed_ip_ranges)
            .field("denied_ip_ranges", &self.denied_ip_ranges)
            .field("static_dns_mapping", &self.static_dns_mapping)
            .field("allowed_headers", &self.allowed_headers)
            .field("denied_headers", &self.denied_headers)
            .field("allowed_url_paths", &self.allowed_url_paths)
            .field("denied_url_paths", &self.denied_url_paths)
            .field(
                "allow_non_global_ip_ranges",
                &self.allow_non_global_ip_ranges,
            )
            .field("method_acl_default", &self.method_acl_default)
            .field("host_acl_default", &self.host_acl_default)
            .field("port_acl_default", &self.port_acl_default)
            .field("ip_acl_default", &self.ip_acl_default)
            .field("header_acl_default", &self.header_acl_default)
            .field("url_path_acl_default", &self.url_path_acl_default)
            .finish()
    }
}

impl PartialEq for HttpAclBuilder {
    fn eq(&self, other: &Self) -> bool {
        self.allow_http == other.allow_http
            && self.allow_https == other.allow_https
            && self.allowed_methods == other.allowed_methods
            && self.denied_methods == other.denied_methods
            && self.allowed_hosts == other.allowed_hosts
            && self.denied_hosts == other.denied_hosts
            && self.allowed_port_ranges == other.allowed_port_ranges
            && self.denied_port_ranges == other.denied_port_ranges
            && self.allowed_ip_ranges == other.allowed_ip_ranges
            && self.denied_ip_ranges == other.denied_ip_ranges
            && self.static_dns_mapping == other.static_dns_mapping
            && self.allowed_headers == other.allowed_headers
            && self.denied_headers == other.denied_headers
            && self.allowed_url_paths == other.allowed_url_paths
            && self.denied_url_paths == other.denied_url_paths
            && self.allow_non_global_ip_ranges == other.allow_non_global_ip_ranges
            && self.method_acl_default == other.method_acl_default
            && self.host_acl_default == other.host_acl_default
            && self.port_acl_default == other.port_acl_default
            && self.ip_acl_default == other.ip_acl_default
            && self.header_acl_default == other.header_acl_default
            && self.url_path_acl_default == other.url_path_acl_default
    }
}

impl HttpAclBuilder {
    /// Create a new [`HttpAclBuilder`].
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
            allowed_headers: HashMap::new(),
            denied_headers: HashMap::new(),
            allowed_url_paths: Vec::new(),
            allowed_url_paths_router: Router::new(),
            denied_url_paths: Vec::new(),
            denied_url_paths_router: Router::new(),
            allow_non_global_ip_ranges: false,
            static_dns_mapping: HashMap::new(),
            method_acl_default: false,
            host_acl_default: false,
            port_acl_default: false,
            ip_acl_default: false,
            header_acl_default: true,
            url_path_acl_default: true,
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

    /// Sets whether non-global IP ranges are allowed.
    ///
    /// Non-global IP ranges include private, loopback, link-local, and other special-use addresses.
    pub fn non_global_ip_ranges(mut self, allow: bool) -> Self {
        self.allow_non_global_ip_ranges = allow;
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

    /// Set default action for headers if no ACL match is found.
    pub fn header_acl_default(mut self, allow: bool) -> Self {
        self.header_acl_default = allow;
        self
    }

    /// Set default action for URL paths if no ACL match is found.
    pub fn url_path_acl_default(mut self, allow: bool) -> Self {
        self.url_path_acl_default = allow;
        self
    }

    /// Adds a method to the allowed methods.
    pub fn add_allowed_method(
        mut self,
        method: impl Into<HttpRequestMethod>,
    ) -> Result<Self, AddError> {
        let method = method.into();
        if self.denied_methods.contains(&method) {
            Err(AddError::AlreadyDeniedMethod(method))
        } else if self.allowed_methods.contains(&method) {
            Err(AddError::AlreadyAllowedMethod(method))
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
                return Err(AddError::AlreadyDeniedMethod(method.clone()));
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
            Err(AddError::AlreadyAllowedMethod(method))
        } else if self.denied_methods.contains(&method) {
            Err(AddError::AlreadyDeniedMethod(method))
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
                return Err(AddError::AlreadyAllowedMethod(method.clone()));
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
                Err(AddError::AlreadyDeniedHost(host))
            } else if self.allowed_hosts.contains(&host) {
                Err(AddError::AlreadyAllowedHost(host))
            } else {
                self.allowed_hosts.push(host);
                Ok(self)
            }
        } else {
            Err(AddError::InvalidEntity(host))
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
                    return Err(AddError::AlreadyDeniedHost(host.clone()));
                }
            } else {
                return Err(AddError::InvalidEntity(host.clone()));
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
                Err(AddError::AlreadyAllowedHost(host))
            } else if self.denied_hosts.contains(&host) {
                Err(AddError::AlreadyDeniedHost(host))
            } else {
                self.denied_hosts.push(host);
                Ok(self)
            }
        } else {
            Err(AddError::InvalidEntity(host))
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
                    return Err(AddError::AlreadyAllowedHost(host.clone()));
                }
            } else {
                return Err(AddError::InvalidEntity(host.clone()));
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
            Err(AddError::AlreadyDeniedPortRange(port_range))
        } else if self.allowed_port_ranges.contains(&port_range) {
            Err(AddError::AlreadyAllowedPortRange(port_range))
        } else if utils::range_overlaps(&self.allowed_port_ranges, &port_range, None)
            || utils::range_overlaps(&self.denied_port_ranges, &port_range, None)
        {
            Err(AddError::Overlaps(format!("{port_range:?}")))
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
        for (i, port_range) in port_ranges.iter().enumerate() {
            if self.denied_port_ranges.contains(port_range) {
                return Err(AddError::AlreadyDeniedPortRange(port_range.clone()));
            } else if utils::range_overlaps(&port_ranges, port_range, Some(i))
                || utils::range_overlaps(&self.denied_port_ranges, port_range, None)
            {
                return Err(AddError::Overlaps(format!("{port_range:?}")));
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
            Err(AddError::AlreadyAllowedPortRange(port_range))
        } else if self.denied_port_ranges.contains(&port_range) {
            Err(AddError::AlreadyDeniedPortRange(port_range))
        } else if utils::range_overlaps(&self.allowed_port_ranges, &port_range, None)
            || utils::range_overlaps(&self.denied_port_ranges, &port_range, None)
        {
            Err(AddError::Overlaps(format!("{port_range:?}")))
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
                return Err(AddError::AlreadyAllowedPortRange(port_range.clone()));
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
    pub fn add_allowed_ip_range<Ip: IntoIpRange>(mut self, ip_range: Ip) -> Result<Self, AddError> {
        let ip_range = ip_range
            .into_range()
            .ok_or_else(|| AddError::InvalidEntity("Invalid IP range".to_string()))?;
        if self.denied_ip_ranges.contains(&ip_range) {
            return Err(AddError::AlreadyDeniedIpRange(ip_range));
        } else if self.allowed_ip_ranges.contains(&ip_range) {
            return Err(AddError::AlreadyAllowedIpRange(ip_range));
        } else if utils::range_overlaps(&self.allowed_ip_ranges, &ip_range, None)
            || utils::range_overlaps(&self.denied_ip_ranges, &ip_range, None)
        {
            return Err(AddError::Overlaps(format!("{ip_range:?}")));
        }
        self.allowed_ip_ranges.push(ip_range);
        Ok(self)
    }

    /// Removes an IP range from the allowed IP ranges.
    pub fn remove_allowed_ip_range<Ip: IntoIpRange>(
        mut self,
        ip_range: Ip,
    ) -> Result<Self, AddError> {
        let ip_range = ip_range
            .into_range()
            .ok_or_else(|| AddError::InvalidEntity("Invalid IP range".to_string()))?;
        self.allowed_ip_ranges.retain(|ip| ip != &ip_range);
        Ok(self)
    }

    /// Sets the allowed IP ranges.
    pub fn allowed_ip_ranges<Ip: IntoIpRange>(
        mut self,
        ip_ranges: Vec<Ip>,
    ) -> Result<Self, AddError> {
        let ip_ranges = ip_ranges
            .into_iter()
            .map(|ip| ip.into_range())
            .collect::<Option<Vec<_>>>()
            .ok_or_else(|| AddError::InvalidEntity("Invalid IP range".to_string()))?;
        for (i, ip_range) in ip_ranges.iter().enumerate() {
            if self.denied_ip_ranges.contains(ip_range) {
                return Err(AddError::AlreadyDeniedIpRange(ip_range.clone()));
            } else if utils::range_overlaps(&ip_ranges, ip_range, Some(i))
                || utils::range_overlaps(&self.denied_ip_ranges, ip_range, None)
            {
                return Err(AddError::Overlaps(format!("{ip_range:?}")));
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
    pub fn add_denied_ip_range<Ip: IntoIpRange>(mut self, ip_range: Ip) -> Result<Self, AddError> {
        let ip_range = ip_range
            .into_range()
            .ok_or_else(|| AddError::InvalidEntity("Invalid IP range".to_string()))?;
        if self.allowed_ip_ranges.contains(&ip_range) {
            return Err(AddError::AlreadyAllowedIpRange(ip_range));
        } else if self.denied_ip_ranges.contains(&ip_range) {
            return Err(AddError::AlreadyDeniedIpRange(ip_range));
        } else if utils::range_overlaps(&self.allowed_ip_ranges, &ip_range, None)
            || utils::range_overlaps(&self.denied_ip_ranges, &ip_range, None)
        {
            return Err(AddError::Overlaps(format!("{ip_range:?}")));
        }
        self.denied_ip_ranges.push(ip_range);
        Ok(self)
    }

    /// Removes an IP range from the denied IP ranges.
    pub fn remove_denied_ip_range<Ip: IntoIpRange>(
        mut self,
        ip_range: Ip,
    ) -> Result<Self, AddError> {
        let ip_range = ip_range
            .into_range()
            .ok_or_else(|| AddError::InvalidEntity("Invalid IP range".to_string()))?;
        self.denied_ip_ranges.retain(|ip| ip != &ip_range);
        Ok(self)
    }

    /// Sets the denied IP ranges.
    pub fn denied_ip_ranges<Ip: IntoIpRange>(
        mut self,
        ip_ranges: Vec<Ip>,
    ) -> Result<Self, AddError> {
        let ip_ranges = ip_ranges
            .into_iter()
            .map(|ip| ip.into_range())
            .collect::<Option<Vec<_>>>()
            .ok_or_else(|| AddError::InvalidEntity("Invalid IP range".to_string()))?;
        for (i, ip_range) in ip_ranges.iter().enumerate() {
            if self.allowed_ip_ranges.contains(ip_range) {
                return Err(AddError::AlreadyAllowedIpRange(ip_range.clone()));
            } else if utils::range_overlaps(&ip_ranges, ip_range, Some(i))
                || utils::range_overlaps(&self.allowed_ip_ranges, ip_range, None)
            {
                return Err(AddError::Overlaps(format!("{ip_range:?}")));
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
            if let Entry::Vacant(e) = self.static_dns_mapping.entry(host.clone()) {
                e.insert(sock_addr);
                Ok(self)
            } else {
                Err(AddError::AlreadyPresentStaticDnsMapping(host, sock_addr))
            }
        } else {
            Err(AddError::InvalidEntity(host))
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
                if self.static_dns_mapping.contains_key(host) {
                    return Err(AddError::AlreadyPresentStaticDnsMapping(host.clone(), *ip));
                }
                self.static_dns_mapping.insert(host.to_string(), *ip);
            } else {
                return Err(AddError::InvalidEntity(host.clone()));
            }
        }
        Ok(self)
    }

    /// Clears the static DNS mappings.
    pub fn clear_static_dns_mappings(mut self) -> Self {
        self.static_dns_mapping.clear();
        self
    }

    /// Adds a header to the allowed headers.
    pub fn add_allowed_header(
        mut self,
        header: String,
        value: Option<String>,
    ) -> Result<Self, AddError> {
        if self.denied_headers.contains_key(&header) {
            Err(AddError::AlreadyDeniedHeader(header, value.clone()))
        } else if let Entry::Vacant(e) = self.allowed_headers.entry(header.clone()) {
            e.insert(value);
            Ok(self)
        } else {
            Err(AddError::AlreadyAllowedHeader(header, value))
        }
    }

    /// Removes a header from the allowed headers.
    pub fn remove_allowed_header(mut self, header: &str) -> Self {
        self.allowed_headers.remove(header);
        self
    }

    /// Sets the allowed headers.
    pub fn allowed_headers(
        mut self,
        headers: HashMap<String, Option<String>>,
    ) -> Result<Self, AddError> {
        for (header, value) in &headers {
            if self.denied_headers.contains_key(header) {
                return Err(AddError::AlreadyDeniedHeader(header.clone(), value.clone()));
            }
        }
        self.allowed_headers = headers;
        Ok(self)
    }

    /// Clears the allowed headers.
    pub fn clear_allowed_headers(mut self) -> Self {
        self.allowed_headers.clear();
        self
    }

    /// Adds a header to the denied headers.
    pub fn add_denied_header(
        mut self,
        header: String,
        value: Option<String>,
    ) -> Result<Self, AddError> {
        if self.allowed_headers.contains_key(&header) {
            Err(AddError::AlreadyAllowedHeader(header, value.clone()))
        } else if let Entry::Vacant(e) = self.denied_headers.entry(header.clone()) {
            e.insert(value);
            Ok(self)
        } else {
            Err(AddError::AlreadyDeniedHeader(header, value))
        }
    }

    /// Removes a header from the denied headers.
    pub fn remove_denied_header(mut self, header: &str) -> Self {
        self.denied_headers.remove(header);
        self
    }

    /// Sets the denied headers.
    pub fn denied_headers(
        mut self,
        headers: HashMap<String, Option<String>>,
    ) -> Result<Self, AddError> {
        for (header, value) in &headers {
            if self.allowed_headers.contains_key(header) {
                return Err(AddError::AlreadyAllowedHeader(
                    header.clone(),
                    value.clone(),
                ));
            }
        }
        self.denied_headers = headers;
        Ok(self)
    }

    /// Clears the denied headers.
    pub fn clear_denied_headers(mut self) -> Self {
        self.denied_headers.clear();
        self
    }

    /// Adds a URL path to the allowed URL paths.
    pub fn add_allowed_url_path(mut self, url_path: String) -> Result<Self, AddError> {
        if self.denied_url_paths.contains(&url_path)
            || self.denied_url_paths_router.at(&url_path).is_ok()
        {
            Err(AddError::AlreadyDeniedUrlPath(url_path))
        } else if self.allowed_url_paths.contains(&url_path)
            || self.allowed_url_paths_router.at(&url_path).is_ok()
        {
            Err(AddError::AlreadyAllowedUrlPath(url_path))
        } else {
            self.allowed_url_paths.push(url_path.clone());
            self.allowed_url_paths_router
                .insert(url_path, ())
                .map_err(|_| AddError::InvalidEntity("Invalid URL path".to_string()))?;
            Ok(self)
        }
    }

    /// Removes a URL path from the allowed URL paths.
    pub fn remove_allowed_url_path(mut self, url_path: &str) -> Self {
        self.allowed_url_paths.retain(|p| p != url_path);
        self.allowed_url_paths_router = {
            let mut router = Router::new();
            for url_path in &self.allowed_url_paths {
                router
                    .insert(url_path.clone(), ())
                    .expect("failed to insert url path");
            }
            router
        };
        self
    }

    /// Sets the allowed URL paths.
    pub fn allowed_url_paths(mut self, url_paths: Vec<String>) -> Result<Self, AddError> {
        for url_path in &url_paths {
            if self.denied_url_paths.contains(url_path)
                || self.denied_url_paths_router.at(url_path).is_ok()
            {
                return Err(AddError::AlreadyDeniedUrlPath(url_path.clone()));
            }
        }
        self.allowed_url_paths_router = Router::new();
        for url_path in &url_paths {
            self.allowed_url_paths_router
                .insert(url_path.clone(), ())
                .map_err(|_| AddError::InvalidEntity(format!("Invalid URL path: {url_path}")))?;
        }
        self.allowed_url_paths = url_paths;
        Ok(self)
    }

    /// Clears the allowed URL paths.
    pub fn clear_allowed_url_paths(mut self) -> Self {
        self.allowed_url_paths.clear();
        self.allowed_url_paths_router = Router::new();
        self
    }

    /// Adds a URL path to the denied URL paths.
    pub fn add_denied_url_path(mut self, url_path: String) -> Result<Self, AddError> {
        if self.allowed_url_paths.contains(&url_path)
            || self.allowed_url_paths_router.at(&url_path).is_ok()
        {
            Err(AddError::AlreadyAllowedUrlPath(url_path))
        } else if self.denied_url_paths.contains(&url_path)
            || self.denied_url_paths_router.at(&url_path).is_ok()
        {
            Err(AddError::AlreadyDeniedUrlPath(url_path))
        } else {
            self.denied_url_paths.push(url_path.clone());
            self.denied_url_paths_router
                .insert(url_path, ())
                .map_err(|_| AddError::InvalidEntity("Invalid URL path".to_string()))?;
            Ok(self)
        }
    }

    /// Removes a URL path from the denied URL paths.
    pub fn remove_denied_url_path(mut self, url_path: &str) -> Self {
        self.denied_url_paths.retain(|p| p != url_path);
        self.denied_url_paths_router = {
            let mut router = Router::new();
            for url_path in &self.denied_url_paths {
                router
                    .insert(url_path.clone(), ())
                    .expect("failed to insert url path");
            }
            router
        };
        self
    }

    /// Sets the denied URL paths.
    pub fn denied_url_paths(mut self, url_paths: Vec<String>) -> Result<Self, AddError> {
        for url_path in &url_paths {
            if self.allowed_url_paths.contains(url_path)
                || self.allowed_url_paths_router.at(url_path).is_ok()
            {
                return Err(AddError::AlreadyAllowedUrlPath(url_path.clone()));
            }
        }
        self.denied_url_paths_router = Router::new();
        for url_path in &url_paths {
            self.denied_url_paths_router
                .insert(url_path.clone(), ())
                .map_err(|_| AddError::InvalidEntity(format!("Invalid URL path: {url_path}")))?;
        }
        self.denied_url_paths = url_paths;
        Ok(self)
    }

    /// Clears the denied URL paths.
    pub fn clear_denied_url_paths(mut self) -> Self {
        self.denied_url_paths.clear();
        self.denied_url_paths_router = Router::new();
        self
    }

    /// Builds the [`HttpAcl`].
    pub fn build(self) -> HttpAcl {
        self.build_full(None)
    }

    /// Builds the [`HttpAcl`].
    pub fn build_full(self, validate_fn: Option<ValidateFn>) -> HttpAcl {
        HttpAcl {
            allow_http: self.allow_http,
            allow_https: self.allow_https,
            allowed_methods: self.allowed_methods.into_iter().collect(),
            denied_methods: self.denied_methods.into_iter().collect(),
            allowed_hosts: self
                .allowed_hosts
                .into_iter()
                .map(|x| x.into_boxed_str())
                .collect(),
            denied_hosts: self
                .denied_hosts
                .into_iter()
                .map(|x| x.into_boxed_str())
                .collect(),
            allowed_port_ranges: self.allowed_port_ranges.into_boxed_slice(),
            denied_port_ranges: self.denied_port_ranges.into_boxed_slice(),
            allowed_ip_ranges: self.allowed_ip_ranges.into_boxed_slice(),
            denied_ip_ranges: self.denied_ip_ranges.into_boxed_slice(),
            allowed_headers: self
                .allowed_headers
                .into_iter()
                .map(|(k, v)| (k.into_boxed_str(), v.map(|s| s.into_boxed_str())))
                .collect(),
            denied_headers: self
                .denied_headers
                .into_iter()
                .map(|(k, v)| (k.into_boxed_str(), v.map(|s| s.into_boxed_str())))
                .collect(),
            allowed_url_paths_router: self.allowed_url_paths_router,
            denied_url_paths_router: self.denied_url_paths_router,
            static_dns_mapping: self
                .static_dns_mapping
                .into_iter()
                .map(|(k, v)| (k.into_boxed_str(), v))
                .collect(),
            validate_fn,
            allow_non_global_ip_ranges: self.allow_non_global_ip_ranges,
            method_acl_default: self.method_acl_default,
            host_acl_default: self.host_acl_default,
            port_acl_default: self.port_acl_default,
            ip_acl_default: self.ip_acl_default,
            header_acl_default: self.header_acl_default,
            url_path_acl_default: self.url_path_acl_default,
        }
    }

    /// Builds the [`HttpAcl`] and returns an error if the configuration is invalid.
    /// This is used for deserialized ACLs as the URL Path Routers need to be built.
    pub fn try_build_full(mut self, validate_fn: Option<ValidateFn>) -> Result<HttpAcl, AddError> {
        if !utils::has_unique_elements(&self.allowed_methods) {
            return Err(AddError::NotUnique(
                "Allowed methods must be unique.".to_string(),
            ));
        }
        for method in &self.allowed_methods {
            if self.denied_methods.contains(method) {
                return Err(AddError::BothAllowedAndDenied(format!(
                    "Method `{}`",
                    method.as_str()
                )));
            }
        }
        if !utils::has_unique_elements(&self.denied_methods) {
            return Err(AddError::NotUnique(
                "Denied methods must be unique.".to_string(),
            ));
        }
        for method in &self.denied_methods {
            if self.allowed_methods.contains(method) {
                return Err(AddError::BothAllowedAndDenied(format!(
                    "Method `{}`",
                    method.as_str()
                )));
            }
        }
        if !utils::has_unique_elements(&self.allowed_hosts) {
            return Err(AddError::NotUnique(
                "Allowed hosts must be unique.".to_string(),
            ));
        }
        for host in &self.allowed_hosts {
            if !utils::authority::is_valid_host(host) {
                return Err(AddError::InvalidEntity(host.to_string()));
            }
            if self.denied_hosts.contains(host) {
                return Err(AddError::BothAllowedAndDenied(format!("Host `{host}`")));
            }
        }
        if !utils::has_unique_elements(&self.denied_hosts) {
            return Err(AddError::NotUnique(
                "Denied hosts must be unique.".to_string(),
            ));
        }
        for host in &self.denied_hosts {
            if !utils::authority::is_valid_host(host) {
                return Err(AddError::InvalidEntity(host.to_string()));
            }
            if self.allowed_hosts.contains(host) {
                return Err(AddError::BothAllowedAndDenied(format!("Host `{host}`")));
            }
        }
        if !utils::has_unique_elements(&self.allowed_port_ranges) {
            return Err(AddError::NotUnique(
                "Allowed port ranges must be unique.".to_string(),
            ));
        }
        if utils::has_overlapping_ranges(&self.allowed_port_ranges) {
            return Err(AddError::Overlaps(
                "Allowed port ranges must not overlap.".to_string(),
            ));
        }
        for port_range in &self.allowed_port_ranges {
            if self.denied_port_ranges.contains(port_range) {
                return Err(AddError::BothAllowedAndDenied(format!(
                    "Port range `{port_range:?}`"
                )));
            }
        }
        if !utils::has_unique_elements(&self.denied_port_ranges) {
            return Err(AddError::NotUnique(
                "Denied port ranges must be unique.".to_string(),
            ));
        }
        if utils::has_overlapping_ranges(&self.denied_port_ranges) {
            return Err(AddError::Overlaps(
                "Denied port ranges must not overlap.".to_string(),
            ));
        }
        for port_range in &self.denied_port_ranges {
            if self.allowed_port_ranges.contains(port_range) {
                return Err(AddError::BothAllowedAndDenied(format!(
                    "Port range `{port_range:?}`"
                )));
            }
        }
        if !utils::has_unique_elements(&self.allowed_ip_ranges) {
            return Err(AddError::NotUnique(
                "Allowed IP ranges must be unique.".to_string(),
            ));
        }
        if utils::has_overlapping_ranges(&self.allowed_ip_ranges) {
            return Err(AddError::Overlaps(
                "Allowed IP ranges must not overlap.".to_string(),
            ));
        }
        for ip_range in &self.allowed_ip_ranges {
            if self.denied_ip_ranges.contains(ip_range) {
                return Err(AddError::BothAllowedAndDenied(format!(
                    "IP range `{ip_range:?}`"
                )));
            }
        }
        if !utils::has_unique_elements(&self.denied_ip_ranges) {
            return Err(AddError::NotUnique(
                "Denied IP ranges must be unique.".to_string(),
            ));
        }
        if utils::has_overlapping_ranges(&self.denied_ip_ranges) {
            return Err(AddError::Overlaps(
                "Denied IP ranges must not overlap.".to_string(),
            ));
        }
        for ip_range in &self.denied_ip_ranges {
            if self.allowed_ip_ranges.contains(ip_range) {
                return Err(AddError::BothAllowedAndDenied(format!(
                    "IP range `{ip_range:?}`"
                )));
            }
        }
        if !utils::has_unique_elements(&self.static_dns_mapping) {
            return Err(AddError::NotUnique(
                "Static DNS mapping must be unique.".to_string(),
            ));
        }
        for host in self.static_dns_mapping.keys() {
            if !utils::authority::is_valid_host(host) {
                return Err(AddError::InvalidEntity(host.to_string()));
            }
        }
        if !utils::has_unique_elements(&self.allowed_url_paths) {
            return Err(AddError::NotUnique(
                "Allowed URL paths must be unique.".to_string(),
            ));
        }
        for url_path in &self.allowed_url_paths {
            if self.denied_url_paths.contains(url_path)
                || self.denied_url_paths_router.at(url_path).is_ok()
            {
                return Err(AddError::BothAllowedAndDenied(format!(
                    "URL path `{url_path}`"
                )));
            } else if self.allowed_url_paths_router.at(url_path).is_err() {
                self.allowed_url_paths_router
                    .insert(url_path.clone(), ())
                    .map_err(|_| {
                        AddError::InvalidEntity(format!(
                            "Failed to insert allowed URL path `{url_path}`."
                        ))
                    })?;
            }
        }
        if !utils::has_unique_elements(&self.denied_url_paths) {
            return Err(AddError::NotUnique(
                "Denied URL paths must be unique.".to_string(),
            ));
        }
        for url_path in &self.denied_url_paths {
            if self.allowed_url_paths.contains(url_path)
                || self.allowed_url_paths_router.at(url_path).is_ok()
            {
                return Err(AddError::BothAllowedAndDenied(format!(
                    "URL path `{url_path}`"
                )));
            } else if self.denied_url_paths_router.at(url_path).is_err() {
                self.denied_url_paths_router
                    .insert(url_path.clone(), ())
                    .map_err(|_| {
                        AddError::InvalidEntity(format!(
                            "Failed to insert denied URL path `{url_path}`."
                        ))
                    })?;
            }
        }
        Ok(self.build_full(validate_fn))
    }

    /// Builds the [`HttpAcl`] and returns an error if the configuration is invalid.
    /// This is used for deserialized ACLs as the URL Path Routers need to be built.
    pub fn try_build(self) -> Result<HttpAcl, AddError> {
        self.try_build_full(None)
    }
}
