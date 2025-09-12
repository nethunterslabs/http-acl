//! Error types for the HTTP ACL library.

use crate::acl::HttpRequestMethod;
use std::net::{IpAddr, SocketAddr};
use std::ops::RangeInclusive;

use thiserror::Error;

/// Represents an error that can occur when adding a new allowed or denied entity to an ACL.
#[non_exhaustive]
#[derive(Clone, Debug, Eq, Hash, PartialEq, Error)]
pub enum AddError {
    /// The HTTP method is already allowed.
    #[error("The HTTP method `{0:?}` is already allowed.")]
    AlreadyAllowedMethod(HttpRequestMethod),
    /// The HTTP method is already denied.
    #[error("The HTTP method `{0:?}` is already denied.")]
    AlreadyDeniedMethod(HttpRequestMethod),
    /// The host is already allowed.
    #[error("The host `{0}` is already allowed.")]
    AlreadyAllowedHost(String),
    /// The host is already denied.
    #[error("The host `{0}` is already denied.")]
    AlreadyDeniedHost(String),
    /// The port range is already allowed.
    #[error("The port range `{0:?}` is already allowed.")]
    AlreadyAllowedPortRange(RangeInclusive<u16>),
    /// The port range is already denied.
    #[error("The port range `{0:?}` is already denied.")]
    AlreadyDeniedPortRange(RangeInclusive<u16>),
    /// The IP range is already allowed.
    #[error("The IP range `{0:?}` is already allowed.")]
    AlreadyAllowedIpRange(RangeInclusive<IpAddr>),
    /// The IP range is already denied.
    #[error("The IP range `{0:?}` is already denied.")]
    AlreadyDeniedIpRange(RangeInclusive<IpAddr>),
    /// The IP range is not a global IP range.
    /// This error is returned if the ACL is configured to disallow non-global IP ranges.
    #[error(
        "The IP range `{0:?}` is not a global IP range, and non-global IP ranges are not allowed."
    )]
    NonGlobalIpRange(RangeInclusive<IpAddr>),
    /// The header is already allowed.
    #[error("The header `{0}` is already allowed.")]
    AlreadyAllowedHeader(String, Option<String>),
    /// The header is already denied.
    #[error("The header `{0}` is already denied.")]
    AlreadyDeniedHeader(String, Option<String>),
    /// The URL path is already allowed.
    #[error("The URL path `{0}` is already allowed.")]
    AlreadyAllowedUrlPath(String),
    /// The URL path is already denied.
    #[error("The URL path `{0}` is already denied.")]
    AlreadyDeniedUrlPath(String),
    /// The static DNS mapping is already present.
    #[error("The static DNS mapping for `{0}`-`{1}` is already present.")]
    AlreadyPresentStaticDnsMapping(String, SocketAddr),
    /// The entity is not allowed or denied because it is invalid.
    #[error("The entity `{0}` is not allowed or denied because it is invalid.")]
    InvalidEntity(String),
    /// The entity is not unique.
    #[error("The entity `{0}` is not unique.")]
    NotUnique(String),
    /// The entity overlaps with another.
    #[error("The entity `{0}` overlaps with another.")]
    Overlaps(String),
    /// The entity is both allowed and denied.
    #[error("The entity `{0}` is both allowed and denied.")]
    BothAllowedAndDenied(String),
    /// General error with a message.
    #[error("An error occurred: `{0}`")]
    Error(String),
}
