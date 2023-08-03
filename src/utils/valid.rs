/// Checks if a host is valid or if it is a valid IP address.
pub(crate) fn is_valid_host(host: &str) -> bool {
    url::Host::parse(host).is_ok() || host.parse::<std::net::IpAddr>().is_ok()
}
