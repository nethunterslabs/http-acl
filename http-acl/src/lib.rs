#![doc = include_str!("../README.md")]
#![warn(missing_docs)]

pub use ipnet::IpNet;

pub mod acl;
pub mod error;
pub mod utils;

pub use acl::{HttpAcl, HttpAclBuilder};

#[cfg(test)]
mod tests {
    use super::HttpAclBuilder;
    use ipnet::IpNet;

    #[test]
    fn acl() {
        let acl = HttpAclBuilder::new()
            .add_allowed_host("example.com".to_string())
            .unwrap()
            .add_allowed_host("example.org".to_string())
            .unwrap()
            .add_denied_host("example.net".to_string())
            .unwrap()
            .add_allowed_port_range(8080..=8080)
            .unwrap()
            .add_denied_port_range(8443..=8443)
            .unwrap()
            .add_allowed_ip_range("1.0.0.0/8".parse::<IpNet>().unwrap())
            .unwrap()
            .add_denied_ip_range("9.0.0.0/8".parse::<IpNet>().unwrap())
            .unwrap()
            .build();

        assert!(acl.is_host_allowed("example.com").is_allowed());
        assert!(acl.is_host_allowed("example.org").is_allowed());
        assert!(!acl.is_host_allowed("example.net").is_allowed());
        assert!(acl.is_port_allowed(8080).is_allowed());
        assert!(!acl.is_port_allowed(8443).is_allowed());
        assert!(acl.is_ip_allowed(&"1.1.1.1".parse().unwrap()).is_allowed());
        assert!(acl.is_ip_allowed(&"9.9.9.9".parse().unwrap()).is_denied());
        assert!(acl
            .is_ip_allowed(&"192.168.1.1".parse().unwrap())
            .is_denied());
    }

    #[test]
    fn host_acl() {
        let acl = HttpAclBuilder::new()
            .add_allowed_host("example.com".to_string())
            .unwrap()
            .add_allowed_host("example.org".to_string())
            .unwrap()
            .add_denied_host("example.net".to_string())
            .unwrap()
            .build();

        assert!(acl.is_host_allowed("example.com").is_allowed());
        assert!(acl.is_host_allowed("example.org").is_allowed());
        assert!(!acl.is_host_allowed("example.net").is_allowed());
    }

    #[test]
    fn port_acl() {
        let acl = HttpAclBuilder::new()
            .clear_allowed_port_ranges()
            .add_allowed_port_range(8080..=8080)
            .unwrap()
            .add_denied_port_range(8443..=8443)
            .unwrap()
            .build();

        assert!(acl.is_port_allowed(8080).is_allowed());
        assert!(!acl.is_port_allowed(8443).is_allowed());
    }

    #[test]
    fn ip_acl() {
        let acl = HttpAclBuilder::new()
            .clear_allowed_ip_ranges()
            .add_allowed_ip_range("1.0.0.0/8".parse::<IpNet>().unwrap())
            .unwrap()
            .add_denied_ip_range("9.0.0.0/8".parse::<IpNet>().unwrap())
            .unwrap()
            .build();

        assert!(acl.is_ip_allowed(&"1.1.1.1".parse().unwrap()).is_allowed());
        assert!(acl.is_ip_allowed(&"9.9.9.9".parse().unwrap()).is_denied());
        assert!(acl
            .is_ip_allowed(&"192.168.1.1".parse().unwrap())
            .is_denied());
    }

    #[test]
    fn private_ip_acl() {
        let acl = HttpAclBuilder::new()
            .private_ip_ranges(true)
            .ip_acl_default(true)
            .build();

        assert!(acl
            .is_ip_allowed(&"192.168.1.1".parse().unwrap())
            .is_allowed());
    }

    #[test]
    fn default_ip_acl() {
        let acl = HttpAclBuilder::new().build();

        assert!(acl
            .is_ip_allowed(&"192.168.1.1".parse().unwrap())
            .is_denied());
        assert!(acl.is_ip_allowed(&"1.1.1.1".parse().unwrap()).is_denied());
        assert!(!acl.is_port_allowed(8080).is_allowed());
    }

    #[test]
    fn url_path_acl() {
        let acl = HttpAclBuilder::new()
            .add_allowed_url_path("/allowed".to_string())
            .unwrap()
            .add_allowed_url_path("/allowed/:id".to_string())
            .unwrap()
            .add_denied_url_path("/denied".to_string())
            .unwrap()
            .add_denied_url_path("/denied/{*path}".to_string())
            .unwrap()
            .build();

        assert!(acl.is_url_path_allowed("/allowed").is_allowed());
        assert!(acl.is_url_path_allowed("/allowed/allowed").is_allowed());
        assert!(acl.is_url_path_allowed("/denied").is_denied());
        assert!(acl.is_url_path_allowed("/denied/denied").is_denied());
        assert!(acl.is_url_path_allowed("/denied/denied/denied").is_denied());
    }
}
