# http-acl

An ACL for HTTP requests.

## Why?

Systems which allow users to create arbitrary HTTP requests or specify arbitrary URLs to fetch like webhooks are vulnerable to SSRF attacks. An example is a malicious user could own a domain which resolves to a private IP address and then use that domain to make requests to internal services.

This crate provides a simple ACL to allow you to specify which hosts, ports, and IP ranges are allowed to be accessed. The ACL can then be used to ensure that the user's request meets the ACL's requirements before the request is made.

## Usage

```rust
use http_acl::HttpAcl;

fn main() -> Result<(), Box<dyn std::error::Error>> {
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

    Ok(())
}
```

## Documentation

See [docs.rs](https://docs.rs/http-acl).
