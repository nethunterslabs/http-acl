//! Error types for the HTTP ACL library.

use crate::acl::HttpRequestMethod;
use std::net::{IpAddr, SocketAddr};
use std::ops::RangeInclusive;

/// Represents an error that can occur when adding a new allowed or denied entity to an ACL.
#[non_exhaustive]
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum AddError {
    /// The HTTP method is already allowed.
    AlreadyAllowedMethod(HttpRequestMethod),
    /// The HTTP method is already denied.
    AlreadyDeniedMethod(HttpRequestMethod),
    /// The host is already allowed.
    AlreadyAllowedHost(String),
    /// The host is already denied.
    AlreadyDeniedHost(String),
    /// The port range is already allowed.
    AlreadyAllowedPortRange(RangeInclusive<u16>),
    /// The port range is already denied.
    AlreadyDeniedPortRange(RangeInclusive<u16>),
    /// The IP range is already allowed.
    AlreadyAllowedIpRange(RangeInclusive<IpAddr>),
    /// The IP range is already denied.
    AlreadyDeniedIpRange(RangeInclusive<IpAddr>),
    /// The header is already allowed.
    AlreadyAllowedHeader(String, Option<String>),
    /// The header is already denied.
    AlreadyDeniedHeader(String, Option<String>),
    /// The URL path is already allowed.
    AlreadyAllowedUrlPath(String),
    /// The URL path is already denied.
    AlreadyDeniedUrlPath(String),
    /// The static DNS mapping is already present.
    AlreadyPresentStaticDnsMapping(String, SocketAddr),
    /// The entity is not allowed or denied because it is invalid.
    InvalidEntity(String),
    /// The entity is not unique.
    NotUnique(String),
    /// The entity overlaps with another.
    Overlaps(String),
    /// The entity is both allowed and denied.
    BothAllowedAndDenied(String),
    /// General error with a message.
    Error(String),
}
