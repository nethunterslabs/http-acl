#![doc = include_str!("../README.md")]
#![warn(missing_docs)]

pub use ipnet::IpNet;

pub mod acl;
pub mod error;
pub mod utils;

pub use acl::{AclClassification, HttpAcl, HttpAclBuilder, HttpRequestMethod};
pub use utils::IntoIpRange;

#[cfg(test)]
mod tests {
    use std::net::IpAddr;
    use std::sync::Arc;

    use ipnet::IpNet;

    use super::{AclClassification, HttpAclBuilder};

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
            .try_build()
            .unwrap();

        assert!(acl.is_host_allowed("example.com").is_allowed());
        assert!(acl.is_host_allowed("example.org").is_allowed());
        assert!(!acl.is_host_allowed("example.net").is_allowed());
        assert!(acl.is_port_allowed(8080).is_allowed());
        assert!(!acl.is_port_allowed(8443).is_allowed());
        assert!(acl.is_ip_allowed(&"1.1.1.1".parse().unwrap()).is_allowed());
        assert!(acl.is_ip_allowed(&"9.9.9.9".parse().unwrap()).is_denied());
        assert!(
            acl.is_ip_allowed(&"192.168.1.1".parse().unwrap())
                .is_denied()
        );
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
            .try_build()
            .unwrap();

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
            .add_denied_port_range(8441..=8443)
            .unwrap()
            .try_build()
            .unwrap();

        assert!(acl.is_port_allowed(80).is_denied());
        assert!(acl.is_port_allowed(8080).is_allowed());
        assert!(acl.is_port_allowed(8440).is_denied());
        assert!(!acl.is_port_allowed(8441).is_allowed());
        assert!(!acl.is_port_allowed(8442).is_allowed());
        assert!(!acl.is_port_allowed(8443).is_allowed());
        assert!(acl.is_port_allowed(8444).is_denied());
    }

    #[test]
    fn ip_acl() {
        let acl = HttpAclBuilder::new()
            .clear_allowed_ip_ranges()
            .add_allowed_ip_range("1.0.0.0/8".parse::<IpNet>().unwrap())
            .unwrap()
            .add_denied_ip_range("9.0.0.0/8".parse::<IpNet>().unwrap())
            .unwrap()
            .try_build()
            .unwrap();

        assert!(acl.is_ip_allowed(&"1.1.1.1".parse().unwrap()).is_allowed());
        assert!(acl.is_ip_allowed(&"9.9.9.9".parse().unwrap()).is_denied());
        assert!(
            acl.is_ip_allowed(&"192.168.1.1".parse().unwrap())
                .is_denied()
        );
    }

    #[test]
    fn private_ip_acl() {
        let acl = HttpAclBuilder::new()
            .private_ip_ranges(true)
            .ip_acl_default(true)
            .try_build()
            .unwrap();

        assert!(
            acl.is_ip_allowed(&"192.168.1.1".parse().unwrap())
                .is_allowed()
        );
        assert!(
            acl.is_ip_allowed(&"203.0.113.12".parse().unwrap())
                .is_allowed()
        );

        let acl = HttpAclBuilder::new()
            .ip_acl_default(true)
            .try_build()
            .unwrap();

        assert!(
            acl.is_ip_allowed(&"192.168.1.1".parse().unwrap())
                .is_denied()
        );
        assert!(
            acl.is_ip_allowed(&"203.0.113.12".parse().unwrap())
                .is_denied()
        );
    }

    #[test]
    fn default_ip_acl() {
        let acl = HttpAclBuilder::new().try_build().unwrap();

        assert!(
            acl.is_ip_allowed(&"192.168.1.1".parse().unwrap())
                .is_denied()
        );
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
            .try_build()
            .unwrap();

        assert!(acl.is_url_path_allowed("/allowed").is_allowed());
        assert!(acl.is_url_path_allowed("/allowed/allowed").is_allowed());
        assert!(acl.is_url_path_allowed("/denied").is_denied());
        assert!(acl.is_url_path_allowed("/denied/denied").is_denied());
        assert!(acl.is_url_path_allowed("/denied/denied/denied").is_denied());
    }

    #[test]
    fn header_acl() {
        let acl = HttpAclBuilder::new()
            .add_allowed_header("X-Allowed".to_string(), Some("true".to_string()))
            .unwrap()
            .add_allowed_header("X-Allowed2".to_string(), None)
            .unwrap()
            .add_denied_header("X-Denied".to_string(), Some("true".to_string()))
            .unwrap()
            .add_denied_header("X-Denied2".to_string(), None)
            .unwrap()
            .try_build()
            .unwrap();

        assert!(acl.is_header_allowed("X-Allowed", "true").is_allowed());
        assert!(acl.is_header_allowed("X-Allowed2", "false").is_allowed());
        assert!(acl.is_header_allowed("X-Denied", "true").is_denied());
        assert!(acl.is_header_allowed("X-Denied2", "false").is_denied());
    }

    #[test]
    fn valid_acl() {
        let acl = HttpAclBuilder::new()
            .try_build_full(Some(Arc::new(|scheme, authority, headers, body| {
                if scheme == "http" {
                    return AclClassification::DeniedUserAcl;
                }

                if authority.host.is_ip() {
                    return AclClassification::DeniedUserAcl;
                }

                for (header_name, header_value) in headers {
                    if header_name == "<dangerous-header>" && header_value == "<dangerous-value>" {
                        return AclClassification::DeniedUserAcl;
                    }
                }

                if let Some(body) = body
                    && body == b"<dangerous-body>"
                {
                    return AclClassification::DeniedUserAcl;
                }

                AclClassification::AllowedDefault
            })))
            .unwrap();

        assert!(
            acl.is_valid(
                "https",
                &"example.com".into(),
                [("<header>", "<value>")].into_iter(),
                Some(b"body"),
            )
            .is_allowed()
        );
        assert!(
            acl.is_valid(
                "http",
                &"example.com".into(),
                [("<header>", "<value>")].into_iter(),
                Some(b"body"),
            )
            .is_denied()
        );
        assert!(
            acl.is_valid(
                "https",
                &"1.1.1.1".parse::<IpAddr>().unwrap().into(),
                [("<header>", "<value>")].into_iter(),
                Some(b"body"),
            )
            .is_denied()
        );
        assert!(
            acl.is_valid(
                "https",
                &"example.com".into(),
                [("<dangerous-header>", "<dangerous-value>")].into_iter(),
                Some(b"body"),
            )
            .is_denied()
        );
        assert!(
            acl.is_valid(
                "https",
                &"example.com".into(),
                [("<header>", "<value>")].into_iter(),
                Some(b"<dangerous-body>"),
            )
            .is_denied()
        );
    }
}
