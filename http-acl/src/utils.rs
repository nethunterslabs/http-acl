//! Utility functions for the http-acl crate.

use std::collections::HashSet;
use std::hash::Hash;
use std::net::IpAddr;
use std::ops::RangeInclusive;

use ipnet::IpNet;

pub mod authority;
pub(crate) mod ip;
pub mod url;

// Taken from https://stackoverflow.com/a/46767732
pub(crate) fn has_unique_elements<T>(iter: T) -> bool
where
    T: IntoIterator,
    T::Item: Eq + Hash,
{
    let mut uniq = HashSet::new();
    iter.into_iter().all(move |x| uniq.insert(x))
}

/// Converts a type into an IP range.
pub trait IntoIpRange {
    /// Converts the type into an IP range.
    fn into_range(self) -> Option<RangeInclusive<IpAddr>>;

    /// Validates the IP range.
    fn validate(ip_range: RangeInclusive<IpAddr>) -> Option<RangeInclusive<IpAddr>> {
        if ip_range.start() <= ip_range.end() {
            Some(ip_range)
        } else {
            None
        }
    }
}

impl IntoIpRange for IpNet {
    fn into_range(self) -> Option<RangeInclusive<IpAddr>> {
        let start = self.network();
        let end = self.broadcast();
        Some(start..=end)
    }
}

impl IntoIpRange for RangeInclusive<IpAddr> {
    fn into_range(self) -> Option<RangeInclusive<IpAddr>> {
        Self::validate(self)
    }
}

impl IntoIpRange for (IpAddr, IpAddr) {
    fn into_range(self) -> Option<RangeInclusive<IpAddr>> {
        Self::validate(self.0..=self.1)
    }
}
